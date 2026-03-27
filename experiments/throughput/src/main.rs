//! End-to-end throughput test: RESP3 vs BRESP vs Protobuf over TCP.
//!
//! Sends N requests through a real socket to measure whether protocol
//! encoding differences matter in practice (spoiler: probably not).
//!
//! Usage:
//!   cargo run -p throughput --release -- --help
//!   cargo run -p throughput --release -- server --format resp3
//!   cargo run -p throughput --release -- client --format resp3 -n 100000

use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::{Parser, Subcommand, ValueEnum};
use prost::Message;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy, ValueEnum, Debug)]
enum Format {
    Resp3,
    Bresp,
    Proto,
}

#[derive(Parser)]
#[command(name = "throughput", about = "RESP encoding throughput test over TCP")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the echo server
    Server {
        #[arg(short, long, default_value = "127.0.0.1:9999")]
        addr: String,
        #[arg(short, long, value_enum, default_value = "resp3")]
        format: Format,
    },
    /// Run the client benchmark
    Client {
        #[arg(short, long, default_value = "127.0.0.1:9999")]
        addr: String,
        #[arg(short, long, value_enum, default_value = "resp3")]
        format: Format,
        /// Number of requests to send
        #[arg(short, long, default_value = "100000")]
        num: usize,
    },
    /// Run server + client together (easiest way to test)
    Both {
        #[arg(short, long, value_enum, default_value = "resp3")]
        format: Format,
        #[arg(short, long, default_value = "100000")]
        num: usize,
    },
}

// ---------------------------------------------------------------------------
// Encoding helpers: each format needs encode_request, encode_response,
// and a way to read one frame from a stream.
// ---------------------------------------------------------------------------

/// Encode a SET key value command in the given format.
fn encode_request(format: Format, key: &[u8], value: &[u8]) -> Vec<u8> {
    match format {
        Format::Resp3 => {
            let frame = resp_rs::resp3::Frame::Array(Some(vec![
                resp_rs::resp3::Frame::BulkString(Some(Bytes::from_static(b"SET"))),
                resp_rs::resp3::Frame::BulkString(Some(Bytes::copy_from_slice(key))),
                resp_rs::resp3::Frame::BulkString(Some(Bytes::copy_from_slice(value))),
            ]));
            resp_rs::resp3::frame_to_bytes(&frame).to_vec()
        }
        Format::Bresp => {
            let frame = bresp::Frame::Array(Some(vec![
                bresp::Frame::BulkString(Some(Bytes::from_static(b"SET"))),
                bresp::Frame::BulkString(Some(Bytes::copy_from_slice(key))),
                bresp::Frame::BulkString(Some(Bytes::copy_from_slice(value))),
            ]));
            bresp::frame_to_bytes(&frame).to_vec()
        }
        Format::Proto => {
            let frame = proto_resp::resp3_to_proto(&resp_rs::resp3::Frame::Array(Some(vec![
                resp_rs::resp3::Frame::BulkString(Some(Bytes::from_static(b"SET"))),
                resp_rs::resp3::Frame::BulkString(Some(Bytes::copy_from_slice(key))),
                resp_rs::resp3::Frame::BulkString(Some(Bytes::copy_from_slice(value))),
            ])));
            // Length-prefix the protobuf message so we know where it ends
            let encoded = frame.encode_to_vec();
            let mut buf = Vec::with_capacity(4 + encoded.len());
            buf.put_u32(encoded.len() as u32);
            buf.extend_from_slice(&encoded);
            buf
        }
    }
}

/// Encode a +OK response in the given format.
fn encode_response(format: Format) -> Vec<u8> {
    match format {
        Format::Resp3 => {
            let frame = resp_rs::resp3::Frame::SimpleString(Bytes::from_static(b"OK"));
            resp_rs::resp3::frame_to_bytes(&frame).to_vec()
        }
        Format::Bresp => {
            let frame = bresp::Frame::SimpleString(Bytes::from_static(b"OK"));
            bresp::frame_to_bytes(&frame).to_vec()
        }
        Format::Proto => {
            let frame = proto_resp::resp3_to_proto(&resp_rs::resp3::Frame::SimpleString(
                Bytes::from_static(b"OK"),
            ));
            let encoded = frame.encode_to_vec();
            let mut buf = Vec::with_capacity(4 + encoded.len());
            buf.put_u32(encoded.len() as u32);
            buf.extend_from_slice(&encoded);
            buf
        }
    }
}

/// Read one frame from a TCP stream. Returns number of bytes consumed.
async fn read_one_frame(
    stream: &mut TcpStream,
    buf: &mut BytesMut,
    format: Format,
) -> std::io::Result<bool> {
    loop {
        // Try to parse from what we have
        if !buf.is_empty() {
            let frozen = buf.clone().freeze();
            let consumed = match format {
                Format::Resp3 => {
                    match resp_rs::resp3::parse_frame(frozen) {
                        Ok((_, rest)) => Some(buf.len() - rest.len()),
                        Err(resp_rs::ParseError::Incomplete) => None,
                        Err(_) => return Ok(false),
                    }
                }
                Format::Bresp => {
                    match bresp::parse_frame(frozen) {
                        Ok((_, rest)) => Some(buf.len() - rest.len()),
                        Err(bresp::ParseError::Incomplete) => None,
                        Err(_) => return Ok(false),
                    }
                }
                Format::Proto => {
                    // Length-prefixed: 4-byte u32 + message
                    if buf.len() < 4 {
                        None
                    } else {
                        let len =
                            u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
                        if buf.len() >= 4 + len {
                            let _ = proto_resp::pb::Frame::decode(&buf[4..4 + len])
                                .map_err(|e| {
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
                                })?;
                            Some(4 + len)
                        } else {
                            None
                        }
                    }
                }
            };

            if let Some(n) = consumed {
                buf.advance(n);
                return Ok(true);
            }
        }

        // Need more data
        let n = stream.read_buf(buf).await?;
        if n == 0 {
            return Ok(false);
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

async fn run_server(addr: &str, format: Format) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    eprintln!("[server] listening on {addr} ({format:?})");

    let response = encode_response(format);

    loop {
        let (mut stream, peer) = listener.accept().await?;
        eprintln!("[server] connection from {peer}");
        let response = response.clone();

        tokio::spawn(async move {
            let mut buf = BytesMut::with_capacity(4096);
            loop {
                match read_one_frame(&mut stream, &mut buf, format).await {
                    Ok(true) => {
                        if stream.write_all(&response).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

async fn run_client(addr: &str, format: Format, num: usize) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.set_nodelay(true)?;
    eprintln!("[client] connected to {addr} ({format:?}), sending {num} requests");

    let request = encode_request(format, b"key", b"value");
    let mut buf = BytesMut::with_capacity(4096);

    let start = Instant::now();

    for _ in 0..num {
        stream.write_all(&request).await?;
        read_one_frame(&mut stream, &mut buf, format).await?;
    }

    let elapsed = start.elapsed();
    let rps = num as f64 / elapsed.as_secs_f64();
    let us_per_req = elapsed.as_micros() as f64 / num as f64;

    println!();
    println!("=== {format:?} Results ===");
    println!("  Requests:      {num}");
    println!("  Total time:    {elapsed:.2?}");
    println!("  Throughput:    {rps:.0} req/s");
    println!("  Latency:       {us_per_req:.1} us/req");
    println!("  Wire size:     {} bytes/req, {} bytes/resp", request.len(), encode_response(format).len());

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Server { addr, format } => run_server(&addr, format).await,
        Command::Client { addr, format, num } => run_client(&addr, format, num).await,
        Command::Both { format, num } => {
            let addr = "127.0.0.1:0";
            let listener = TcpListener::bind(addr).await?;
            let bound_addr = listener.local_addr()?;
            let addr_str = bound_addr.to_string();
            eprintln!("[both] server on {addr_str} ({format:?})");

            let response = encode_response(format);

            // Spawn server
            tokio::spawn(async move {
                loop {
                    if let Ok((mut stream, _)) = listener.accept().await {
                        let response = response.clone();
                        tokio::spawn(async move {
                            let mut buf = BytesMut::with_capacity(4096);
                            loop {
                                match read_one_frame(&mut stream, &mut buf, format).await {
                                    Ok(true) => {
                                        if stream.write_all(&response).await.is_err() {
                                            break;
                                        }
                                    }
                                    _ => break,
                                }
                            }
                        });
                    }
                }
            });

            // Small delay for server to start
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;

            run_client(&addr_str, format, num).await
        }
    }
}
