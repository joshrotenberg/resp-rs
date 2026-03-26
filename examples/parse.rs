//! Basic parsing and serialization demo.
//!
//! Run with: `cargo run --example parse`

use bytes::Bytes;

fn main() {
    // --- RESP2 ---
    println!("=== RESP2 ===\n");

    // Parse a simple string
    let data = Bytes::from("+OK\r\n");
    let (frame, _) = resp_rs::resp2::parse_frame(data).unwrap();
    println!("Simple string: {frame:?}");

    // Parse an array (a SET command)
    let data = Bytes::from("*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n");
    let (frame, _) = resp_rs::resp2::parse_frame(data).unwrap();
    println!("SET command:   {frame:?}");

    // Serialize a frame back to wire format
    let frame = resp_rs::resp2::Frame::Array(Some(vec![
        resp_rs::resp2::Frame::BulkString(Some(Bytes::from("GET"))),
        resp_rs::resp2::Frame::BulkString(Some(Bytes::from("mykey"))),
    ]));
    let wire = resp_rs::resp2::frame_to_bytes(&frame);
    println!("Serialized:    {:?}", String::from_utf8_lossy(&wire));

    // --- RESP3 ---
    println!("\n=== RESP3 ===\n");

    // Parse RESP3-specific types
    let cases: &[(&str, &[u8])] = &[
        ("Null", b"_\r\n"),
        ("Boolean", b"#t\r\n"),
        ("Double", b",3.14159\r\n"),
        (
            "Big number",
            b"(3492890328409238509324850943850943825024385\r\n",
        ),
        ("Verbatim", b"=15\r\ntxt:hello world\r\n"),
    ];
    for (label, raw) in cases {
        let (frame, _) = resp_rs::resp3::parse_frame(Bytes::from(*raw)).unwrap();
        println!("{label:12}:  {frame:?}");
    }

    // Parse a map
    let data = Bytes::from("%2\r\n+name\r\n$5\r\nAlice\r\n+age\r\n:30\r\n");
    let (frame, _) = resp_rs::resp3::parse_frame(data).unwrap();
    println!("{:12}:  {frame:?}", "Map");

    // --- Streaming parser ---
    println!("\n=== Streaming parser ===\n");

    let mut parser = resp_rs::resp2::Parser::new();

    // Feed partial data
    parser.feed(Bytes::from("*2\r\n$4\r\nPIN"));
    println!(
        "Fed partial data, buffered {} bytes",
        parser.buffered_bytes()
    );
    println!("Next frame: {:?}", parser.next_frame().unwrap());

    // Feed the rest
    parser.feed(Bytes::from("G\r\n$0\r\n\r\n"));
    println!("Fed remaining data");
    let frame = parser.next_frame().unwrap().unwrap();
    println!("Got frame:  {frame:?}");
}
