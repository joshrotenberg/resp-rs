//! Breadis: a bread-themed Redis-compatible server powered by resp-rs.
//!
//! Speaks RESP2 over TCP and supports artisanal bread commands.
//! Connect with `redis-cli -p 6380` and start baking!
//!
//! # Commands
//!
//! - `KNEAD <dough> <minutes>` -- Knead a dough for the given minutes
//! - `PROOF <dough>` -- Proof a dough (sets it to "proofing")
//! - `BAKE <dough> <temp>` -- Bake a dough at the given temperature
//! - `CHECK <dough>` -- Check the status of a dough
//! - `TOSS <dough>` -- Throw out a dough
//! - `MENU` -- List all doughs in the bakery
//! - `PING [message]` -- Classic ping
//! - `COMMAND` -- Required for redis-cli compatibility
//!
//! Run with: `cargo run --example breadis`

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use bytes::Bytes;
use resp_rs::resp2::{self, Frame, Parser};

fn main() {
    let listener = TcpListener::bind("127.0.0.1:6380").expect("failed to bind to port 6380");
    println!("Breadis is rising on port 6380...");
    println!("Connect with: redis-cli -p 6380");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| handle_client(stream));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}

fn handle_client(mut stream: TcpStream) {
    let peer = stream.peer_addr().ok();
    println!("[{peer:?}] new baker connected");

    let mut bakery: HashMap<String, String> = HashMap::new();
    let mut parser = Parser::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };

        parser.feed(Bytes::copy_from_slice(&buf[..n]));

        while let Ok(Some(frame)) = parser.next_frame() {
            let response = handle_command(&frame, &mut bakery);
            let wire = resp2::frame_to_bytes(&response);
            if stream.write_all(&wire).is_err() {
                return;
            }
        }
    }

    println!("[{peer:?}] baker disconnected");
}

fn handle_command(frame: &Frame, bakery: &mut HashMap<String, String>) -> Frame {
    let args = match frame {
        Frame::Array(Some(items)) => items,
        _ => return error("ERR expected array command"),
    };

    if args.is_empty() {
        return error("ERR empty command");
    }

    let cmd = match extract_string(&args[0]) {
        Some(s) => s.to_uppercase(),
        None => return error("ERR invalid command"),
    };

    match cmd.as_str() {
        "KNEAD" => {
            if args.len() != 3 {
                return error("ERR usage: KNEAD <dough> <minutes>");
            }
            let dough = match extract_string(&args[1]) {
                Some(s) => s,
                None => return error("ERR invalid dough name"),
            };
            let minutes = match extract_string(&args[2]) {
                Some(s) => s,
                None => return error("ERR invalid minutes"),
            };
            let status = format!("kneaded for {minutes} minutes");
            bakery.insert(dough.clone(), status);
            Frame::SimpleString(Bytes::from(format!(
                "Kneading {dough}... the gluten is developing!"
            )))
        }
        "PROOF" => {
            if args.len() != 2 {
                return error("ERR usage: PROOF <dough>");
            }
            let dough = match extract_string(&args[1]) {
                Some(s) => s,
                None => return error("ERR invalid dough name"),
            };
            if !bakery.contains_key(&dough) {
                return error("ERR that dough doesn't exist yet. KNEAD it first!");
            }
            bakery.insert(dough.clone(), "proofing... rising nicely".to_string());
            Frame::SimpleString(Bytes::from(format!("Proofing {dough}... let it rise!")))
        }
        "BAKE" => {
            if args.len() != 3 {
                return error("ERR usage: BAKE <dough> <temp>");
            }
            let dough = match extract_string(&args[1]) {
                Some(s) => s,
                None => return error("ERR invalid dough name"),
            };
            let temp = match extract_string(&args[2]) {
                Some(s) => s,
                None => return error("ERR invalid temperature"),
            };
            if !bakery.contains_key(&dough) {
                return error("ERR that dough doesn't exist yet. KNEAD it first!");
            }
            bakery.insert(dough.clone(), format!("baking at {temp}F"));
            Frame::SimpleString(Bytes::from(format!(
                "Baking {dough} at {temp}F... smells amazing!"
            )))
        }
        "CHECK" => {
            if args.len() != 2 {
                return error("ERR usage: CHECK <dough>");
            }
            let dough = match extract_string(&args[1]) {
                Some(s) => s,
                None => return error("ERR invalid dough name"),
            };
            match bakery.get(&dough) {
                Some(status) => Frame::BulkString(Some(Bytes::from(format!("{dough}: {status}")))),
                None => Frame::BulkString(None),
            }
        }
        "TOSS" => {
            if args.len() != 2 {
                return error("ERR usage: TOSS <dough>");
            }
            let dough = match extract_string(&args[1]) {
                Some(s) => s,
                None => return error("ERR invalid dough name"),
            };
            match bakery.remove(&dough) {
                Some(_) => Frame::SimpleString(Bytes::from(format!(
                    "{dough} tossed in the bin. A sad day for bread."
                ))),
                None => error("ERR nothing to toss -- that dough doesn't exist"),
            }
        }
        "MENU" => {
            if bakery.is_empty() {
                return Frame::Array(Some(vec![]));
            }
            let items: Vec<Frame> = bakery
                .iter()
                .map(|(k, v)| Frame::BulkString(Some(Bytes::from(format!("{k}: {v}")))))
                .collect();
            Frame::Array(Some(items))
        }
        "PING" => {
            if args.len() > 1 {
                match extract_string(&args[1]) {
                    Some(msg) => Frame::BulkString(Some(Bytes::from(msg))),
                    None => Frame::SimpleString(Bytes::from("PONG")),
                }
            } else {
                Frame::SimpleString(Bytes::from("PONG"))
            }
        }
        "COMMAND" => {
            // redis-cli sends COMMAND DOCS on connect; just return empty array
            Frame::Array(Some(vec![]))
        }
        _ => error(&format!(
            "ERR unknown command '{cmd}'. Try KNEAD, PROOF, BAKE, CHECK, TOSS, or MENU"
        )),
    }
}

fn extract_string(frame: &Frame) -> Option<String> {
    match frame {
        Frame::BulkString(Some(b)) => String::from_utf8(b.to_vec()).ok(),
        Frame::SimpleString(b) => String::from_utf8(b.to_vec()).ok(),
        _ => None,
    }
}

fn error(msg: &str) -> Frame {
    Frame::Error(Bytes::from(msg.to_string()))
}
