//! Tokio codec for RESP3 frame encoding and decoding.

use bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::codec::CodecError;
use crate::resp3::{Frame, MAX_DEPTH, parse_frame_inner, try_frame_to_bytes};

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
    /// Frozen unparsed bytes drained out of the read buffer.
    ///
    /// Frames slice out of this, so stepping past one is a refcount bump. The
    /// previous shape cloned the whole read buffer on every `decode` call, and
    /// tokio-util calls `decode` once per frame while the buffer stays
    /// readable, so draining K pipelined frames copied about K*N/2 bytes.
    pending: Bytes,
}

impl Codec {
    /// Create a new RESP3 codec.
    pub fn new() -> Self {
        Self {
            pending: Bytes::new(),
        }
    }

    /// Move anything new in the read buffer into `pending`.
    ///
    /// `BytesMut::split` and `freeze` are both O(1), so the common case of an
    /// empty `pending` costs nothing. A copy happens only when bytes arrive
    /// while an incomplete frame is held, which is once per socket read.
    fn take_from(&mut self, src: &mut BytesMut) {
        if src.is_empty() {
            return;
        }
        if self.pending.is_empty() {
            self.pending = src.split().freeze();
        } else {
            let mut merged = BytesMut::with_capacity(self.pending.len() + src.len());
            merged.extend_from_slice(&self.pending);
            merged.unsplit(src.split());
            self.pending = merged.freeze();
        }
    }
}

impl Decoder for Codec {
    type Item = Frame;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.take_from(src);
        if self.pending.is_empty() {
            return Ok(None);
        }

        match parse_frame_inner(&self.pending, 0, MAX_DEPTH) {
            Ok((frame, consumed)) => {
                self.pending = if consumed == self.pending.len() {
                    // Drop the reference rather than holding an empty slice, so
                    // a drained buffer does not pin its allocation.
                    Bytes::new()
                } else {
                    self.pending.slice(consumed..)
                };
                Ok(Some(frame))
            }
            Err(crate::ParseError::Incomplete) => Ok(None),
            Err(e) => {
                self.pending = Bytes::new();
                Err(e.into())
            }
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // The default implementation decides based on whether `src` is empty,
        // which is now always true because `decode` drains it. Without this
        // override a trailing partial frame would be dropped silently instead
        // of reported as an unexpected EOF.
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if self.pending.is_empty() => Ok(None),
            None => Err(CodecError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "bytes remaining on stream",
            ))),
        }
    }
}

impl Encoder<Frame> for Codec {
    type Error = CodecError;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Checked: a frame that cannot parse back as itself is refused rather
        // than written to the socket. This is the point where a server emits,
        // so it is where the CRLF injection path is closed.
        let bytes = try_frame_to_bytes(&item)?;
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

        // The partial frame is now held by the codec rather than left in the
        // read buffer, which is what lets decode avoid cloning the buffer on
        // every call. The observable contract is unchanged: feeding the rest
        // completes the frame.
        assert!(buf.is_empty());
        buf.extend_from_slice(b"lo\r\n");
        assert_eq!(
            codec.decode(&mut buf).unwrap().unwrap(),
            Frame::BulkString(Some(Bytes::from("hello")))
        );
        assert!(codec.decode(&mut buf).unwrap().is_none());
    }

    #[test]
    fn decode_eof_reports_a_trailing_partial_frame() {
        // decode drains src, so the default decode_eof would see an empty
        // buffer and silently drop a partial frame. The override checks the
        // codec's own pending bytes instead.
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("$5\r\nhel");
        assert!(codec.decode(&mut buf).unwrap().is_none());

        let err = codec.decode_eof(&mut buf).unwrap_err();
        assert!(
            matches!(&err, CodecError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
            "got {err:?}"
        );
    }

    #[test]
    fn decode_eof_on_a_clean_boundary_is_none() {
        let mut codec = Codec::new();
        let mut buf = BytesMut::from("+OK\r\n");
        assert!(codec.decode(&mut buf).unwrap().is_some());
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
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
    fn encode_refuses_a_frame_that_would_split_the_stream() {
        // A server reflecting untrusted input into an error reply is the
        // realistic injection path. encode must refuse rather than emit.
        let hostile = "BAD'\r\n+OK\r\n:9999";
        let reply = Frame::Error(Bytes::from(format!("ERR unknown command '{hostile}")));

        let mut codec = Codec::new();
        let mut buf = BytesMut::new();
        let result = codec.encode(reply, &mut buf);

        assert!(
            matches!(result, Err(CodecError::Serialize(_))),
            "got {result:?}"
        );
        assert!(
            buf.is_empty(),
            "refused frame still wrote {} bytes",
            buf.len()
        );
    }

    #[test]
    fn encode_refuses_a_non_finite_double() {
        // Would come back as SpecialFloat, silently changing type.
        let mut codec = Codec::new();
        let mut buf = BytesMut::new();
        let result = codec.encode(Frame::Double(f64::NAN), &mut buf);
        assert!(
            matches!(result, Err(CodecError::Serialize(_))),
            "got {result:?}"
        );
        assert!(buf.is_empty());
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
