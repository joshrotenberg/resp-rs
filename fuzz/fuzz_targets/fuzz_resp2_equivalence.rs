#![no_main]
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use resp_rs::resp2;

// Given arbitrary bytes, assert that repeatedly calling parse_frame on the
// full buffer yields the same frames as feeding arbitrary chunks into Parser.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // 1. Direct parsing: repeatedly call parse_frame until Incomplete or error.
    let mut direct_frames = Vec::new();
    let mut remaining = Bytes::copy_from_slice(data);
    while let Ok((frame, rest)) = resp2::parse_frame(remaining.clone()) {
        direct_frames.push(frame);
        remaining = rest;
    }

    // 2. Parser: feed the same data in variable-size chunks, collect frames.
    let mut parser = resp2::Parser::new();
    let mut parser_frames = Vec::new();
    let mut i = 0;
    let mut ctrl = 0;

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
                Ok(Some(frame)) => parser_frames.push(frame),
                Ok(None) => break,
                Err(_) => {
                    // On hard error, both paths should have found the same
                    // frames up to this point.
                    assert_eq!(
                        direct_frames[..parser_frames.len()],
                        parser_frames[..],
                        "frames diverged before error"
                    );
                    return;
                }
            }
        }

        i = end;
    }

    // 3. Assert equivalence.
    assert_eq!(
        direct_frames, parser_frames,
        "direct parse and Parser yielded different frames"
    );
});
