//! Tokio codec for RESP2 frame encoding and decoding.

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::codec::CodecError;
use crate::resp2::{Frame, frame_to_bytes, parse_frame_inner};

/// A Tokio codec for RESP2 frames.
///
/// Implements [`Decoder`] and [`Encoder`] for use with
/// [`tokio_util::codec::Framed`], enabling async RESP2 communication
/// over TCP streams.
///
/// # Examples
///
/// ```ignore
/// use resp_rs::resp2::{Codec, Frame};
/// use tokio::net::TcpStream;
/// use tokio_util::codec::Framed;
/// use futures::{SinkExt, StreamExt};
/// use bytes::Bytes;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let stream = TcpStream::connect("127.0.0.1:6379").await?;
/// let mut framed = Framed::new(stream, Codec::new());
///
/// // Send a PING command
/// framed.send(Frame::Array(Some(vec![
///     Frame::BulkString(Some(Bytes::from("PING"))),
/// ]))).await?;
///
/// // Read the response
/// if let Some(Ok(frame)) = framed.next().await {
///     println!("Got: {frame:?}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct Codec {
    _private: (),
}

impl Codec {
    /// Create a new RESP2 codec.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Decoder for Codec {
    type Item = Frame;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.is_empty() {
            return Ok(None);
        }

        let frozen = src.clone().freeze();

        match parse_frame_inner(&frozen, 0) {
            Ok((frame, consumed)) => {
                src.advance(consumed);
                Ok(Some(frame))
            }
            Err(crate::ParseError::Incomplete) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

impl Encoder<Frame> for Codec {
    type Error = CodecError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = frame_to_bytes(&item);
        dst.extend_from_slice(&bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ParseError;
    use bytes::Bytes;
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn decode_simple_string() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("+OK\r\n");
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame, Frame::SimpleString(Bytes::from("OK")));
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_incomplete_returns_none() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("+HEL");
        assert!(codec.decode(&mut buf).unwrap().is_none());
        // Buffer should be preserved
        assert_eq!(buf.as_ref(), b"+HEL");
    }

    #[test]
    fn decode_multiple_frames() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("+OK\r\n:42\r\n");

        let f1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(f1, Frame::SimpleString(Bytes::from("OK")));

        let f2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(f2, Frame::Integer(42));

        assert!(buf.is_empty());
    }

    #[test]
    fn decode_array() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n");
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(
            frame,
            Frame::Array(Some(vec![
                Frame::BulkString(Some(Bytes::from("foo"))),
                Frame::BulkString(Some(Bytes::from("bar"))),
            ]))
        );
    }

    #[test]
    fn decode_error_propagates() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("X\r\n");
        let result = codec.decode(&mut buf);
        assert!(matches!(
            result,
            Err(CodecError::Parse(ParseError::InvalidTag(b'X')))
        ));
    }

    #[test]
    fn encode_simple() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(Frame::SimpleString(Bytes::from("OK")), &mut buf)
            .unwrap();
        assert_eq!(buf.as_ref(), b"+OK\r\n");
    }

    #[test]
    fn encode_array() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(
                Frame::Array(Some(vec![Frame::BulkString(Some(Bytes::from("PING")))])),
                &mut buf,
            )
            .unwrap();
        assert_eq!(buf.as_ref(), b"*1\r\n$4\r\nPING\r\n");
    }

    #[test]
    fn roundtrip_through_codec() {
        let mut codec = Codec::new();
        let original = Frame::Array(Some(vec![
            Frame::BulkString(Some(Bytes::from("SET"))),
            Frame::BulkString(Some(Bytes::from("key"))),
            Frame::BulkString(Some(Bytes::from("value"))),
        ]));

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(original, decoded);
    }
}
