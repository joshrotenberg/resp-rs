#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use resp_rs::resp2::Parser;

fuzz_target!(|data: &[u8]| {
    let mut parser = Parser::new();

    // Split the input at arbitrary points to simulate chunked TCP reads.
    // Use the first byte (mod len+1) as the split point.
    if data.is_empty() {
        return;
    }

    let split_at = (data[0] as usize) % data.len();
    let (chunk1, chunk2) = data.split_at(split_at);

    parser.feed(Bytes::copy_from_slice(chunk1));
    // Drain any frames available after the first chunk.
    loop {
        match parser.next_frame() {
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => return,
        }
    }

    parser.feed(Bytes::copy_from_slice(chunk2));
    // Drain any frames available after the second chunk.
    loop {
        match parser.next_frame() {
            Ok(Some(_)) => continue,
            Ok(None) => break,
            Err(_) => return,
        }
    }
});
