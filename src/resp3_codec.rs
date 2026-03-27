//! Tokio codec for RESP3 frame encoding and decoding.

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::codec::CodecError;
use crate::resp3::{Frame, frame_to_bytes, parse_frame_inner};

/// A Tokio codec for RESP3 frames.
///
/// Implements [`Decoder`] and [`Encoder`] for use with
/// [`tokio_util::codec::Framed`], enabling async RESP3 communication
/// over TCP streams.
///
/// # Examples
///
/// ```ignore
/// use resp_rs::resp3::{Codec, Frame};
/// use tokio::net::TcpStream;
/// use tokio_util::codec::Framed;
/// use futures::{SinkExt, StreamExt};
/// use bytes::Bytes;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let stream = TcpStream::connect("127.0.0.1:6379").await?;
/// let mut framed = Framed::new(stream, Codec::new());
///
/// // Send a HELLO 3 to upgrade to RESP3
/// framed.send(Frame::Array(Some(vec![
///     Frame::BulkString(Some(Bytes::from("HELLO"))),
///     Frame::BulkString(Some(Bytes::from("3"))),
/// ]))).await?;
///
/// // Read the response (RESP3 map)
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
    /// Create a new RESP3 codec.
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
        let mut buf = BytesMut::from("$5\r\nhel");
        assert!(codec.decode(&mut buf).unwrap().is_none());
        assert_eq!(buf.as_ref(), b"$5\r\nhel");
    }

    #[test]
    fn decode_resp3_types() {
        let mut codec = Codec::new();

        // Null
        let mut buf = BytesMut::from("_\r\n");
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), Frame::Null);

        // Boolean
        let mut buf = BytesMut::from("#t\r\n");
        assert_eq!(
            codec.decode(&mut buf).unwrap().unwrap(),
            Frame::Boolean(true)
        );

        // Double
        let mut buf = BytesMut::from(",3.5\r\n");
        assert_eq!(codec.decode(&mut buf).unwrap().unwrap(), Frame::Double(3.5));

        // Map
        let mut buf = BytesMut::from("%1\r\n+key\r\n:1\r\n");
        let frame = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(
            frame,
            Frame::Map(vec![(
                Frame::SimpleString(Bytes::from("key")),
                Frame::Integer(1),
            )])
        );
    }

    #[test]
    fn decode_multiple_frames() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("+OK\r\n:42\r\n#f\r\n");

        let f1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(f1, Frame::SimpleString(Bytes::from("OK")));

        let f2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(f2, Frame::Integer(42));

        let f3 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(f3, Frame::Boolean(false));

        assert!(buf.is_empty());
    }

    #[test]
    fn decode_error_propagates() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("X\r\n");
        assert!(matches!(
            codec.decode(&mut buf),
            Err(CodecError::Parse(ParseError::InvalidTag(b'X')))
        ));
    }

    #[test]
    fn encode_map() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::new();
        codec
            .encode(
                Frame::Map(vec![(
                    Frame::SimpleString(Bytes::from("key")),
                    Frame::Integer(42),
                )]),
                &mut buf,
            )
            .unwrap();
        assert_eq!(buf.as_ref(), b"%1\r\n+key\r\n:42\r\n");
    }

    #[test]
    fn roundtrip_through_codec() {
        let mut codec = Codec::new();
        let original = Frame::Map(vec![
            (
                Frame::SimpleString(Bytes::from("server")),
                Frame::BulkString(Some(Bytes::from("redis"))),
            ),
            (
                Frame::SimpleString(Bytes::from("version")),
                Frame::BulkString(Some(Bytes::from("7.0.0"))),
            ),
        ]);

        let mut buf = BytesMut::new();
        codec.encode(original.clone(), &mut buf).unwrap();
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(original, decoded);
    }
}
