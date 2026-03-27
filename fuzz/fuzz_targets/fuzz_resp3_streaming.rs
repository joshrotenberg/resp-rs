#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use resp_rs::resp3::Parser;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut parser = Parser::new();
    let mut i = 0;
    let mut ctrl = 0;

    // Use leading bytes as chunk-size directives, feed remainder in variable chunks.
    while i < data.len() {
        let step = if ctrl < data.len() {
            (data[ctrl] as usize % 8) + 1
        } else {
            1
        };
        ctrl += 1;

        let end = (i + step).min(data.len());
        parser.feed(Bytes::copy_from_slice(&data[i..end]));

        loop {
            match parser.next_frame() {
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => {
                    // On hard error, buffer must be cleared.
                    assert_eq!(parser.buffered_bytes(), 0);
                    return;
                }
            }
        }

        i = end;
    }
});
