//! Async Redis PING using the Tokio codec.
//!
//! Connects to a Redis server, sends PING, and prints the response.
//!
//! Run with: `cargo run --example ping --features codec`
//!            `cargo run --example ping --features codec -- localhost:6380`
//!
//! Requires a Redis server running at the given address (default: 127.0.0.1:6379).

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use resp_rs::resp2::{Codec, Frame};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:6379".to_string());

    let stream = TcpStream::connect(&addr).await?;
    println!("Connected to {addr}");

    let mut framed = Framed::new(stream, Codec::new());

    // Send PING
    framed
        .send(Frame::Array(Some(vec![Frame::BulkString(Some(
            Bytes::from("PING"),
        ))])))
        .await?;

    if let Some(Ok(frame)) = framed.next().await {
        println!("PING -> {frame:?}");
    }

    Ok(())
}
