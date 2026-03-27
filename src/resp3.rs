//! Zero-copy RESP3 parser.
//!
//! Parses RESP3 frames using `bytes::Bytes` for efficient, zero-copy operation.
//! Supports all RESP3 data types, including fixed-length and streaming variants.

use bytes::{BufMut, Bytes, BytesMut};

/// Maximum reasonable size for collections to prevent DoS attacks.
const MAX_COLLECTION_SIZE: usize = 10_000_000;

/// Maximum reasonable size for bulk string/blob/chunk payloads (512 MB).
const MAX_BULK_STRING_SIZE: usize = 512 * 1024 * 1024;

/// A streaming parser for RESP3 frames.
///
/// This parser allows feeding data in chunks and extracting frames as they become available.
/// It maintains an internal buffer of accumulated data and attempts to parse frames from it.
#[derive(Default, Debug)]
pub struct Parser {
    buffer: BytesMut,
}

impl Parser {
    /// Creates a new parser with an empty buffer.
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    /// Feeds a chunk of data into the parser.
    ///
    /// The data is appended to the internal buffer.
    pub fn feed(&mut self, data: Bytes) {
        self.buffer.extend_from_slice(&data);
    }

    /// Attempts to extract the next complete frame from the buffer.
    ///
    /// Returns `Ok(None)` if there is not enough data to parse a complete frame.
    /// Returns `Ok(Some(frame))` on success, consuming the parsed bytes.
    /// Returns `Err` on protocol errors, clearing the buffer.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, ParseError> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        let bytes = self.buffer.split().freeze();

        match parse_frame_inner(&bytes, 0) {
            Ok((frame, consumed)) => {
                if consumed < bytes.len() {
                    self.buffer.unsplit(BytesMut::from(&bytes[consumed..]));
                }
                Ok(Some(frame))
            }
            Err(ParseError::Incomplete) => {
                self.buffer.unsplit(bytes.into());
                Ok(None)
            }
            Err(e) => {
                // Buffer was emptied by split() above; intentionally not restored
                // on hard errors so the parser doesn't re-parse corrupt data.
                Err(e)
            }
        }
    }

    /// Returns the number of bytes currently in the buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Clears the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

// --- Zero-copy Frame enum and parser using bytes::Bytes ---
/// A parsed RESP3 frame.
///
/// Each variant corresponds to one of the RESP3 types, including both fixed-length
/// and streaming headers for bulk strings, arrays, sets, maps, attributes, and pushes.
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// Simple string: +&lt;string&gt;\r\n
    SimpleString(Bytes),
    /// Simple error: -&lt;error&gt;\r\n
    Error(Bytes),
    /// Integer: :&lt;number&gt;\r\n
    Integer(i64),
    /// Blob string: $&lt;length&gt;\r\n&lt;bytes&gt;\r\n
    // BulkString(Option<Vec<u8>>),
    BulkString(Option<Bytes>),
    /// Blob error: !&lt;length&gt;\r\n&lt;bytes&gt;\r\n
    BlobError(Bytes),
    /// Streaming blob string header: $?\r\n
    StreamedStringHeader,
    /// Streaming blob error header: !?\r\n
    StreamedBlobErrorHeader,
    /// Streaming verbatim string header: =?\r\n
    StreamedVerbatimStringHeader,
    /// Streaming array header: *?\r\n
    StreamedArrayHeader,
    /// Streaming set header: ~?\r\n
    StreamedSetHeader,
    /// Streaming map header: %?\r\n
    StreamedMapHeader,
    /// Streaming attribute header: |?\r\n
    StreamedAttributeHeader,
    /// Streaming push header: >?\r\n
    StreamedPushHeader,
    /// Streaming string chunk: ;length\r\ndata\r\n
    ///
    /// Represents an individual chunk in a streaming string sequence.
    /// These chunks are parsed from `;{length}\r\n{data}\r\n` format.
    /// A zero-length chunk (`;0\r\n`) indicates the end of the stream.
    ///
    /// # Example
    /// ```
    /// use resp_rs::resp3::Frame;
    /// use bytes::Bytes;
    ///
    /// // Chunk containing "Hello"
    /// // Wire format: ;5\r\nHello\r\n
    /// Frame::StreamedStringChunk(Bytes::from("Hello"));
    /// ```
    StreamedStringChunk(Bytes),

    /// Accumulated streaming string data from multiple chunks
    ///
    /// Created by `parse_streaming_sequence()` when parsing a complete
    /// streaming string sequence (`$?\r\n` + chunks + `;0\r\n`).
    /// Contains all chunks in order, allowing reconstruction of the full string.
    ///
    /// # Example
    /// ```
    /// use resp_rs::resp3::Frame;
    /// use bytes::Bytes;
    ///
    /// // Represents "Hello world" from chunks ["Hello ", "world"]
    /// Frame::StreamedString(vec![
    ///     Bytes::from("Hello "),
    ///     Bytes::from("world")
    /// ]);
    /// ```
    StreamedString(Vec<Bytes>),

    /// Accumulated streaming array data from multiple chunks
    ///
    /// Created when parsing a streaming array sequence (`*?\r\n` + frames + `.\r\n`).
    /// Contains all frames that were streamed as part of the array.
    ///
    /// # Example
    /// ```
    /// use resp_rs::resp3::Frame;
    /// use bytes::Bytes;
    ///
    /// // Array with mixed types
    /// Frame::StreamedArray(vec![
    ///     Frame::SimpleString(Bytes::from("hello")),
    ///     Frame::Integer(42),
    ///     Frame::Boolean(true)
    /// ]);
    /// ```
    StreamedArray(Vec<Frame>),

    /// Accumulated streaming set data from multiple chunks
    ///
    /// Created when parsing a streaming set sequence (`~?\r\n` + frames + `.\r\n`).
    /// Contains all unique elements that were streamed as part of the set.
    StreamedSet(Vec<Frame>),

    /// Accumulated streaming map data from multiple chunks
    ///
    /// Created when parsing a streaming map sequence (`%?\r\n` + key-value pairs + `.\r\n`).
    /// Contains all key-value pairs that were streamed as part of the map.
    ///
    /// # Example
    /// ```
    /// use resp_rs::resp3::Frame;
    /// use bytes::Bytes;
    ///
    /// Frame::StreamedMap(vec![
    ///     (Frame::SimpleString(Bytes::from("name")), Frame::SimpleString(Bytes::from("Alice"))),
    ///     (Frame::SimpleString(Bytes::from("age")), Frame::Integer(25))
    /// ]);
    /// ```
    StreamedMap(Vec<(Frame, Frame)>),

    /// Accumulated streaming attribute data from multiple chunks
    ///
    /// Created when parsing a streaming attribute sequence (`|?\r\n` + key-value pairs + `.\r\n`).
    /// Attributes provide out-of-band metadata that doesn't affect the main data structure.
    StreamedAttribute(Vec<(Frame, Frame)>),

    /// Accumulated streaming push data from multiple chunks
    ///
    /// Created when parsing a streaming push sequence (`>?\r\n` + frames + `.\r\n`).
    /// Push messages are server-initiated communications (e.g., pub/sub messages).
    ///
    /// # Example
    /// ```
    /// use resp_rs::resp3::Frame;
    /// use bytes::Bytes;
    ///
    /// // Pub/sub message
    /// Frame::StreamedPush(vec![
    ///     Frame::SimpleString(Bytes::from("pubsub")),
    ///     Frame::SimpleString(Bytes::from("channel1")),
    ///     Frame::SimpleString(Bytes::from("message content"))
    /// ]);
    /// ```
    StreamedPush(Vec<Frame>),
    /// End-of-stream terminator for all chunked sequences: .\r\n
    StreamTerminator,
    /// Null: _\r\n
    Null,
    /// Double: ,&lt;float&gt;\r\n
    Double(f64),
    /// Special Float: ,inf\r\n, -inf\r\n, nan\r\n
    SpecialFloat(Bytes),
    /// Boolean: #t\r\n or #f\r\n
    Boolean(bool),
    /// Big number: (&lt;number&gt;\r\n
    BigNumber(Bytes),
    /// Verbatim string: =format:content\r\n
    // VerbatimString { format: String, content: String },
    VerbatimString(Bytes, Bytes),
    /// Array: *&lt;count&gt;\r\n... (or streaming header *?\r\n)
    Array(Option<Vec<Frame>>),
    /// Set: ~&lt;count&gt;\r\n... (or streaming header ~?\r\n)
    Set(Vec<Frame>),
    /// Map: %&lt;count&gt;\r\n... (or streaming header %?\r\n)
    Map(Vec<(Frame, Frame)>),
    /// Attribute: |&lt;count&gt;\r\n... (or streaming header |?\r\n)
    Attribute(Vec<(Frame, Frame)>),
    /// Push: > &lt;count&gt;\r\n... (or streaming header >?\r\n)
    Push(Vec<Frame>),
}

pub use crate::ParseError;

/// Parse a single RESP3 frame from the provided `Bytes`.
///
/// Returns the parsed `Frame` and the remaining unconsumed `Bytes`, or a `ParseError` on failure.
pub fn parse_frame(input: Bytes) -> Result<(Frame, Bytes), ParseError> {
    let (frame, consumed) = parse_frame_inner(&input, 0)?;
    Ok((frame, input.slice(consumed..)))
}

/// Offset-based internal parser. Works with byte positions to avoid creating
/// intermediate `Bytes::slice()` objects. Only slices for actual frame data.
fn parse_frame_inner(input: &Bytes, pos: usize) -> Result<(Frame, usize), ParseError> {
    let buf = input.as_ref();
    if pos >= buf.len() {
        return Err(ParseError::Incomplete);
    }

    let tag = buf[pos];

    match tag {
        b'+' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            Ok((
                Frame::SimpleString(input.slice(pos + 1..line_end)),
                after_crlf,
            ))
        }
        b'-' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            Ok((Frame::Error(input.slice(pos + 1..line_end)), after_crlf))
        }
        b':' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let v = parse_i64(&buf[pos + 1..line_end])?;
            Ok((Frame::Integer(v), after_crlf))
        }
        b'$' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            // streaming header?
            if len_bytes == b"?" {
                return Ok((Frame::StreamedStringHeader, after_crlf));
            }
            // null bulk
            if len_bytes == b"-1" {
                return Ok((Frame::BulkString(None), after_crlf));
            }
            let len = parse_usize(len_bytes)?;
            if len > MAX_BULK_STRING_SIZE {
                return Err(ParseError::BadLength);
            }
            if len == 0 {
                if after_crlf + 1 >= buf.len() {
                    return Err(ParseError::Incomplete);
                }
                if buf[after_crlf] == b'\r' && buf[after_crlf + 1] == b'\n' {
                    return Ok((Frame::BulkString(Some(Bytes::new())), after_crlf + 2));
                } else {
                    return Err(ParseError::InvalidFormat);
                }
            }
            let data_start = after_crlf;
            let data_end = data_start.checked_add(len).ok_or(ParseError::BadLength)?;
            if data_end + 1 >= buf.len() {
                return Err(ParseError::Incomplete);
            }
            if buf[data_end] != b'\r' || buf[data_end + 1] != b'\n' {
                return Err(ParseError::InvalidFormat);
            }
            Ok((
                Frame::BulkString(Some(input.slice(data_start..data_end))),
                data_end + 2,
            ))
        }
        b'_' => {
            if pos + 2 < buf.len() && buf[pos + 1] == b'\r' && buf[pos + 2] == b'\n' {
                Ok((Frame::Null, pos + 3))
            } else {
                Err(ParseError::Incomplete)
            }
        }
        b',' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let line_bytes = &buf[pos + 1..line_end];
            // special float cases
            if line_bytes == b"inf" || line_bytes == b"-inf" || line_bytes == b"nan" {
                return Ok((
                    Frame::SpecialFloat(input.slice(pos + 1..line_end)),
                    after_crlf,
                ));
            }
            // numeric double
            let s = std::str::from_utf8(line_bytes).map_err(|_| ParseError::Utf8Error)?;
            let v = s.parse::<f64>().map_err(|_| ParseError::InvalidFormat)?;
            // Rust's f64::parse accepts case-insensitive "inf"/"infinity"/"nan".
            // Normalize these to SpecialFloat for consistent roundtripping.
            if v.is_infinite() || v.is_nan() {
                let canonical = if v.is_nan() {
                    "nan"
                } else if v.is_sign_negative() {
                    "-inf"
                } else {
                    "inf"
                };
                return Ok((Frame::SpecialFloat(Bytes::from(canonical)), after_crlf));
            }
            Ok((Frame::Double(v), after_crlf))
        }
        b'#' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            match &buf[pos + 1..line_end] {
                b"t" => Ok((Frame::Boolean(true), after_crlf)),
                b"f" => Ok((Frame::Boolean(false), after_crlf)),
                _ => Err(ParseError::InvalidBoolean),
            }
        }
        b'(' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            Ok((Frame::BigNumber(input.slice(pos + 1..line_end)), after_crlf))
        }
        b'=' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            // streaming header
            if len_bytes == b"?" {
                return Ok((Frame::StreamedVerbatimStringHeader, after_crlf));
            }
            // null case
            if len_bytes == b"-1" {
                return Ok((
                    Frame::VerbatimString(Bytes::new(), Bytes::new()),
                    after_crlf,
                ));
            }
            let len = parse_usize(len_bytes)?;
            if len > MAX_BULK_STRING_SIZE {
                return Err(ParseError::BadLength);
            }
            let data_start = after_crlf;
            let data_end = data_start.checked_add(len).ok_or(ParseError::BadLength)?;
            if data_end + 1 >= buf.len() {
                return Err(ParseError::Incomplete);
            }
            if buf[data_end] != b'\r' || buf[data_end + 1] != b'\n' {
                return Err(ParseError::InvalidFormat);
            }
            // find colon separator in payload
            let sep = buf[data_start..data_end]
                .iter()
                .position(|&b| b == b':')
                .ok_or(ParseError::InvalidFormat)?;
            let format = input.slice(data_start..data_start + sep);
            let content = input.slice(data_start + sep + 1..data_end);
            Ok((Frame::VerbatimString(format, content), data_end + 2))
        }
        b'!' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            // streaming blob error header
            if len_bytes == b"?" {
                return Ok((Frame::StreamedBlobErrorHeader, after_crlf));
            }
            if len_bytes == b"-1" {
                return Ok((Frame::BlobError(Bytes::new()), after_crlf));
            }
            let len = parse_usize(len_bytes)?;
            if len > MAX_BULK_STRING_SIZE {
                return Err(ParseError::BadLength);
            }
            let data_start = after_crlf;
            let data_end = data_start.checked_add(len).ok_or(ParseError::BadLength)?;
            if data_end + 1 >= buf.len() {
                return Err(ParseError::Incomplete);
            }
            if buf[data_end] != b'\r' || buf[data_end + 1] != b'\n' {
                return Err(ParseError::InvalidFormat);
            }
            Ok((
                Frame::BlobError(input.slice(data_start..data_end)),
                data_end + 2,
            ))
        }
        b'*' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            if len_bytes == b"?" {
                return Ok((Frame::StreamedArrayHeader, after_crlf));
            }
            if len_bytes == b"-1" {
                return Ok((Frame::Array(None), after_crlf));
            }
            let count = parse_count(len_bytes)?;
            if count == 0 {
                return Ok((Frame::Array(Some(Vec::new())), after_crlf));
            }
            let mut cursor = after_crlf;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (item, next) = parse_frame_inner(input, cursor)?;
                items.push(item);
                cursor = next;
            }
            Ok((Frame::Array(Some(items)), cursor))
        }
        b'~' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            if len_bytes == b"?" {
                return Ok((Frame::StreamedSetHeader, after_crlf));
            }
            let count = parse_count(len_bytes)?;
            let mut cursor = after_crlf;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (item, next) = parse_frame_inner(input, cursor)?;
                items.push(item);
                cursor = next;
            }
            Ok((Frame::Set(items), cursor))
        }
        b'%' | b'|' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            if len_bytes == b"?" {
                return if tag == b'%' {
                    Ok((Frame::StreamedMapHeader, after_crlf))
                } else {
                    Ok((Frame::StreamedAttributeHeader, after_crlf))
                };
            }
            let count = parse_count(len_bytes)?;
            let mut cursor = after_crlf;
            let mut pairs = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, next1) = parse_frame_inner(input, cursor)?;
                let (val, next2) = parse_frame_inner(input, next1)?;
                pairs.push((key, val));
                cursor = next2;
            }
            if tag == b'%' {
                Ok((Frame::Map(pairs), cursor))
            } else {
                Ok((Frame::Attribute(pairs), cursor))
            }
        }
        b'>' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len_bytes = &buf[pos + 1..line_end];
            if len_bytes == b"?" {
                return Ok((Frame::StreamedPushHeader, after_crlf));
            }
            let count = parse_count(len_bytes)?;
            let mut cursor = after_crlf;
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                let (item, next) = parse_frame_inner(input, cursor)?;
                items.push(item);
                cursor = next;
            }
            Ok((Frame::Push(items), cursor))
        }
        b';' => {
            let (line_end, after_crlf) = find_crlf(buf, pos + 1)?;
            let len = parse_usize(&buf[pos + 1..line_end])?;
            if len > MAX_BULK_STRING_SIZE {
                return Err(ParseError::BadLength);
            }
            if len == 0 {
                if after_crlf + 1 >= buf.len() {
                    return Err(ParseError::Incomplete);
                }
                if buf[after_crlf] == b'\r' && buf[after_crlf + 1] == b'\n' {
                    return Ok((Frame::StreamedStringChunk(Bytes::new()), after_crlf + 2));
                } else {
                    return Err(ParseError::InvalidFormat);
                }
            }
            let data_start = after_crlf;
            let data_end = data_start.checked_add(len).ok_or(ParseError::BadLength)?;
            if data_end + 1 >= buf.len() {
                return Err(ParseError::Incomplete);
            }
            if buf[data_end] != b'\r' || buf[data_end + 1] != b'\n' {
                return Err(ParseError::InvalidFormat);
            }
            Ok((
                Frame::StreamedStringChunk(input.slice(data_start..data_end)),
                data_end + 2,
            ))
        }
        b'.' => {
            if pos + 2 < buf.len() && buf[pos + 1] == b'\r' && buf[pos + 2] == b'\n' {
                Ok((Frame::StreamTerminator, pos + 3))
            } else {
                Err(ParseError::Incomplete)
            }
        }
        _ => Err(ParseError::InvalidTag(tag)),
    }
}

/// Parse a complete RESP3 streaming sequence, accumulating chunks until termination.
///
/// This function handles RESP3 streaming sequences that begin with streaming headers
/// (`$?`, `*?`, `~?`, `%?`, `|?`, `>?`) and accumulates the following data until
/// the appropriate terminator is encountered.
///
/// # Streaming Types Supported
///
/// - **Streaming Strings**: `$?\r\n` followed by chunks terminated with `;0\r\n`
/// - **Streaming Arrays**: `*?\r\n` followed by frames terminated with `.\r\n`
/// - **Streaming Sets**: `~?\r\n` followed by frames terminated with `.\r\n`
/// - **Streaming Maps**: `%?\r\n` followed by key-value pairs terminated with `.\r\n`
/// - **Streaming Attributes**: `|?\r\n` followed by key-value pairs terminated with `.\r\n`
/// - **Streaming Push**: `>?\r\n` followed by frames terminated with `.\r\n`
///
/// # Examples
///
/// ## Streaming String
/// ```rust
/// use resp_rs::resp3::{parse_streaming_sequence, Frame};
/// use bytes::Bytes;
///
/// let data = Bytes::from("$?\r\n;4\r\nHell\r\n;6\r\no worl\r\n;1\r\nd\r\n;0\r\n\r\n");
/// let (frame, rest) = parse_streaming_sequence(data).unwrap();
///
/// if let Frame::StreamedString(chunks) = frame {
///     assert_eq!(chunks.len(), 3);
///     let full_string: String = chunks.iter()
///         .map(|chunk| std::str::from_utf8(chunk).unwrap())
///         .collect::<Vec<_>>()
///         .join("");
///     assert_eq!(full_string, "Hello world");
/// }
/// assert!(rest.is_empty());
/// ```
///
/// ## Streaming Array
/// ```rust
/// use resp_rs::resp3::{parse_streaming_sequence, Frame};
/// use bytes::Bytes;
///
/// let data = Bytes::from("*?\r\n+hello\r\n:42\r\n#t\r\n.\r\n");
/// let (frame, _) = parse_streaming_sequence(data).unwrap();
///
/// if let Frame::StreamedArray(items) = frame {
///     assert_eq!(items.len(), 3);
///     // items[0] = SimpleString("hello")
///     // items[1] = Integer(42)
///     // items[2] = Boolean(true)
/// }
/// ```
///
/// ## Streaming Map
/// ```rust
/// use resp_rs::resp3::{parse_streaming_sequence, Frame};
/// use bytes::Bytes;
///
/// let data = Bytes::from("%?\r\n+key1\r\n+val1\r\n+key2\r\n:123\r\n.\r\n");
/// let (frame, _) = parse_streaming_sequence(data).unwrap();
///
/// if let Frame::StreamedMap(pairs) = frame {
///     assert_eq!(pairs.len(), 2);
///     // pairs[0] = (SimpleString("key1"), SimpleString("val1"))
///     // pairs[1] = (SimpleString("key2"), Integer(123))
/// }
/// ```
///
/// # Errors
///
/// Returns `ParseError::Incomplete` if the stream is not complete or if required
/// terminators are missing. Returns `ParseError::InvalidFormat` for malformed
/// chunk data or unexpected frame types within streaming sequences.
///
/// # Notes
///
/// - For non-streaming frames, this function simply returns the parsed frame
/// - Streaming string chunks are accumulated in order
/// - All other streaming types accumulate complete frames until termination
/// - Zero-copy parsing is used where possible to minimize allocations
pub fn parse_streaming_sequence(input: Bytes) -> Result<(Frame, Bytes), ParseError> {
    if input.is_empty() {
        return Err(ParseError::Incomplete);
    }

    let (header, mut rest) = parse_frame(input)?;

    match header {
        Frame::StreamedStringHeader => {
            // Parse streaming string chunks until zero-length chunk
            let mut chunks = Vec::new();

            loop {
                let (frame, new_rest) = parse_frame(rest)?;
                rest = new_rest;

                match frame {
                    Frame::StreamedStringChunk(chunk) => {
                        if chunk.is_empty() {
                            // Zero-length chunk indicates end of stream
                            break;
                        }
                        chunks.push(chunk);
                    }
                    _ => {
                        return Err(ParseError::InvalidFormat);
                    }
                }
            }

            Ok((Frame::StreamedString(chunks), rest))
        }
        Frame::StreamedBlobErrorHeader => {
            // Parse streaming blob error chunks until zero-length chunk
            // Similar to StreamedStringHeader but for blob errors
            let mut chunks = Vec::new();

            loop {
                let (frame, new_rest) = parse_frame(rest)?;
                rest = new_rest;

                match frame {
                    Frame::BlobError(chunk) => {
                        // Check for terminator by parsing as bulk string
                        // In streaming context, !0\r\n acts as terminator
                        if chunk.is_empty() {
                            break;
                        }
                        chunks.push(chunk);
                    }
                    _ => {
                        return Err(ParseError::InvalidFormat);
                    }
                }
            }

            // Concatenate all error chunks
            let total_len: usize = chunks.iter().map(|c| c.len()).sum();
            let mut combined = Vec::with_capacity(total_len);
            for chunk in chunks {
                combined.extend_from_slice(&chunk);
            }
            Ok((Frame::BlobError(Bytes::from(combined)), rest))
        }
        Frame::StreamedVerbatimStringHeader => {
            // Parse streaming verbatim string chunks until zero-length chunk
            let mut chunks = Vec::new();

            loop {
                let (frame, new_rest) = parse_frame(rest)?;
                rest = new_rest;

                match frame {
                    Frame::VerbatimString(format, content) => {
                        // Zero-length content indicates end of stream
                        if content.is_empty() && format.len() == 3 {
                            break;
                        }
                        // For now, just collect the content parts
                        // In a full implementation, we'd validate format consistency
                        chunks.push((format, content));
                    }
                    _ => {
                        return Err(ParseError::InvalidFormat);
                    }
                }
            }

            // Concatenate all chunks, using format from first chunk
            if chunks.is_empty() {
                return Ok((Frame::VerbatimString(Bytes::new(), Bytes::new()), rest));
            }

            let format = chunks[0].0.clone();
            let total_len: usize = chunks.iter().map(|(_, c)| c.len()).sum();
            let mut combined = Vec::with_capacity(total_len);
            for (_, content) in chunks {
                combined.extend_from_slice(&content);
            }
            Ok((Frame::VerbatimString(format, Bytes::from(combined)), rest))
        }
        Frame::StreamedArrayHeader => {
            // Parse streaming array items until terminator
            let mut items = Vec::new();

            loop {
                let (frame, new_rest) = parse_frame(rest)?;
                rest = new_rest;

                match frame {
                    Frame::StreamTerminator => {
                        break;
                    }
                    item => {
                        items.push(item);
                    }
                }
            }

            Ok((Frame::StreamedArray(items), rest))
        }
        Frame::StreamedSetHeader => {
            // Parse streaming set items until terminator
            let mut items = Vec::new();

            loop {
                let (frame, new_rest) = parse_frame(rest)?;
                rest = new_rest;

                match frame {
                    Frame::StreamTerminator => {
                        break;
                    }
                    item => {
                        items.push(item);
                    }
                }
            }

            Ok((Frame::StreamedSet(items), rest))
        }
        Frame::StreamedMapHeader => {
            // Parse streaming map pairs until terminator
            let mut pairs = Vec::new();

            loop {
                let (frame, new_rest) = parse_frame(rest)?;
                rest = new_rest;

                match frame {
                    Frame::StreamTerminator => {
                        break;
                    }
                    key => {
                        let (value, newer_rest) = parse_frame(rest)?;
                        rest = newer_rest;
                        pairs.push((key, value));
                    }
                }
            }

            Ok((Frame::StreamedMap(pairs), rest))
        }
        Frame::StreamedAttributeHeader => {
            // Parse streaming attribute pairs until terminator
            let mut pairs = Vec::new();

            loop {
                let (frame, new_rest) = parse_frame(rest)?;
                rest = new_rest;

                match frame {
                    Frame::StreamTerminator => {
                        break;
                    }
                    key => {
                        let (value, newer_rest) = parse_frame(rest)?;
                        rest = newer_rest;
                        pairs.push((key, value));
                    }
                }
            }

            Ok((Frame::StreamedAttribute(pairs), rest))
        }
        Frame::StreamedPushHeader => {
            // Parse streaming push items until terminator
            let mut items = Vec::new();

            loop {
                let (frame, new_rest) = parse_frame(rest)?;
                rest = new_rest;

                match frame {
                    Frame::StreamTerminator => {
                        break;
                    }
                    item => {
                        items.push(item);
                    }
                }
            }

            Ok((Frame::StreamedPush(items), rest))
        }
        _ => {
            // Not a streaming sequence, just return the original frame
            Ok((header, rest))
        }
    }
}

/// Find `\r\n` in `buf` starting at `from`. Returns `(line_end, after_crlf)` where
/// `line_end` is the position of `\r` and `after_crlf` is the position after `\n`.
#[inline]
fn find_crlf(buf: &[u8], from: usize) -> Result<(usize, usize), ParseError> {
    let mut i = from;
    let len = buf.len();
    while i + 1 < len {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Ok((i, i + 2));
        }
        i += 1;
    }
    Err(ParseError::Incomplete)
}

/// Parse a `usize` directly from ASCII digit bytes, no UTF-8 validation needed.
#[inline]
fn parse_usize(buf: &[u8]) -> Result<usize, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::BadLength);
    }
    let mut v: usize = 0;
    for &b in buf {
        if !b.is_ascii_digit() {
            return Err(ParseError::BadLength);
        }
        v = v.checked_mul(10).ok_or(ParseError::BadLength)?;
        v = v
            .checked_add((b - b'0') as usize)
            .ok_or(ParseError::BadLength)?;
    }
    Ok(v)
}

/// Parse an `i64` directly from ASCII bytes (optional leading `-`), no UTF-8 validation.
#[inline]
fn parse_i64(buf: &[u8]) -> Result<i64, ParseError> {
    if buf.is_empty() {
        return Err(ParseError::InvalidFormat);
    }
    let (neg, digits) = if buf[0] == b'-' {
        (true, &buf[1..])
    } else {
        (false, buf)
    };
    if digits.is_empty() {
        return Err(ParseError::InvalidFormat);
    }
    let mut v: i64 = 0;
    for (i, &d) in digits.iter().enumerate() {
        if !d.is_ascii_digit() {
            return Err(ParseError::InvalidFormat);
        }
        let digit = (d - b'0') as i64;
        if neg && v == i64::MAX / 10 && digit == 8 && i == digits.len() - 1 {
            return Ok(i64::MIN);
        }
        if v > i64::MAX / 10 || (v == i64::MAX / 10 && digit > i64::MAX % 10) {
            return Err(ParseError::Overflow);
        }
        v = v * 10 + digit;
    }
    if neg { Ok(-v) } else { Ok(v) }
}

/// Parse a collection count (usize) with MAX_COLLECTION_SIZE check.
#[inline]
fn parse_count(buf: &[u8]) -> Result<usize, ParseError> {
    let count = parse_usize(buf)?;
    if count > MAX_COLLECTION_SIZE {
        return Err(ParseError::BadLength);
    }
    Ok(count)
}

/// Converts a Frame to its RESP3 byte representation.
///
/// This function serializes a Frame into the corresponding RESP3 protocol bytes.
pub fn frame_to_bytes(frame: &Frame) -> Bytes {
    let mut buf = BytesMut::new();
    serialize_frame(frame, &mut buf);
    buf.freeze()
}

fn serialize_frame(frame: &Frame, buf: &mut BytesMut) {
    match frame {
        Frame::SimpleString(s) => {
            buf.put_u8(b'+');
            buf.extend_from_slice(s);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::Error(e) => {
            buf.put_u8(b'-');
            buf.extend_from_slice(e);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::Integer(i) => {
            buf.put_u8(b':');
            let s = i.to_string();
            buf.extend_from_slice(s.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        Frame::BulkString(opt) => {
            buf.put_u8(b'$');
            match opt {
                Some(data) => {
                    let len = data.len().to_string();
                    buf.extend_from_slice(len.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                    buf.extend_from_slice(data);
                    buf.extend_from_slice(b"\r\n");
                }
                None => {
                    buf.extend_from_slice(b"-1\r\n");
                }
            }
        }
        Frame::BlobError(data) => {
            buf.put_u8(b'!');
            let len = data.len().to_string();
            buf.extend_from_slice(len.as_bytes());
            buf.extend_from_slice(b"\r\n");
            buf.extend_from_slice(data);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::StreamedStringHeader => {
            buf.extend_from_slice(b"$?\r\n");
        }
        Frame::StreamedBlobErrorHeader => {
            buf.extend_from_slice(b"!?\r\n");
        }
        Frame::StreamedVerbatimStringHeader => {
            buf.extend_from_slice(b"=?\r\n");
        }
        Frame::StreamedArrayHeader => {
            buf.extend_from_slice(b"*?\r\n");
        }
        Frame::StreamedSetHeader => {
            buf.extend_from_slice(b"~?\r\n");
        }
        Frame::StreamedMapHeader => {
            buf.extend_from_slice(b"%?\r\n");
        }
        Frame::StreamedAttributeHeader => {
            buf.extend_from_slice(b"|?\r\n");
        }
        Frame::StreamedPushHeader => {
            buf.extend_from_slice(b">?\r\n");
        }
        Frame::StreamedStringChunk(data) => {
            buf.put_u8(b';');
            let len = data.len().to_string();
            buf.extend_from_slice(len.as_bytes());
            buf.extend_from_slice(b"\r\n");
            buf.extend_from_slice(data);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::StreamedString(chunks) => {
            // Serialize as streaming string sequence: $?\r\n + chunks + terminator
            buf.extend_from_slice(b"$?\r\n");
            for chunk in chunks {
                buf.put_u8(b';');
                let len = chunk.len().to_string();
                buf.extend_from_slice(len.as_bytes());
                buf.extend_from_slice(b"\r\n");
                buf.extend_from_slice(chunk);
                buf.extend_from_slice(b"\r\n");
            }
            buf.extend_from_slice(b";0\r\n\r\n");
        }
        Frame::StreamedArray(items) => {
            buf.extend_from_slice(b"*?\r\n");
            for item in items {
                serialize_frame(item, buf);
            }
            buf.extend_from_slice(b".\r\n");
        }
        Frame::StreamedSet(items) => {
            buf.extend_from_slice(b"~?\r\n");
            for item in items {
                serialize_frame(item, buf);
            }
            buf.extend_from_slice(b".\r\n");
        }
        Frame::StreamedMap(pairs) => {
            buf.extend_from_slice(b"%?\r\n");
            for (key, value) in pairs {
                serialize_frame(key, buf);
                serialize_frame(value, buf);
            }
            buf.extend_from_slice(b".\r\n");
        }
        Frame::StreamedAttribute(pairs) => {
            buf.extend_from_slice(b"|?\r\n");
            for (key, value) in pairs {
                serialize_frame(key, buf);
                serialize_frame(value, buf);
            }
            buf.extend_from_slice(b".\r\n");
        }
        Frame::StreamedPush(items) => {
            buf.extend_from_slice(b">?\r\n");
            for item in items {
                serialize_frame(item, buf);
            }
            buf.extend_from_slice(b".\r\n");
        }
        Frame::StreamTerminator => {
            buf.extend_from_slice(b".\r\n");
        }
        Frame::Null => {
            buf.extend_from_slice(b"_\r\n");
        }
        Frame::Double(d) => {
            buf.put_u8(b',');
            let s = d.to_string();
            buf.extend_from_slice(s.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }
        Frame::SpecialFloat(f) => {
            buf.put_u8(b',');
            buf.extend_from_slice(f);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::Boolean(b) => {
            buf.extend_from_slice(if *b { b"#t\r\n" } else { b"#f\r\n" });
        }
        Frame::BigNumber(n) => {
            buf.put_u8(b'(');
            buf.extend_from_slice(n);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::VerbatimString(format, content) => {
            buf.put_u8(b'=');
            let total_len = format.len() + 1 + content.len(); // +1 for the colon
            let len = total_len.to_string();
            buf.extend_from_slice(len.as_bytes());
            buf.extend_from_slice(b"\r\n");
            buf.extend_from_slice(format);
            buf.put_u8(b':');
            buf.extend_from_slice(content);
            buf.extend_from_slice(b"\r\n");
        }
        Frame::Array(opt) => {
            buf.put_u8(b'*');
            match opt {
                Some(items) => {
                    let len = items.len().to_string();
                    buf.extend_from_slice(len.as_bytes());
                    buf.extend_from_slice(b"\r\n");
                    for item in items {
                        serialize_frame(item, buf);
                    }
                }
                None => {
                    buf.extend_from_slice(b"-1\r\n");
                }
            }
        }
        Frame::Set(items) => {
            buf.put_u8(b'~');
            let len = items.len().to_string();
            buf.extend_from_slice(len.as_bytes());
            buf.extend_from_slice(b"\r\n");
            for item in items {
                serialize_frame(item, buf);
            }
        }
        Frame::Map(pairs) => {
            buf.put_u8(b'%');
            let len = pairs.len().to_string();
            buf.extend_from_slice(len.as_bytes());
            buf.extend_from_slice(b"\r\n");
            for (key, value) in pairs {
                serialize_frame(key, buf);
                serialize_frame(value, buf);
            }
        }
        Frame::Attribute(pairs) => {
            buf.put_u8(b'|');
            let len = pairs.len().to_string();
            buf.extend_from_slice(len.as_bytes());
            buf.extend_from_slice(b"\r\n");
            for (key, value) in pairs {
                serialize_frame(key, buf);
                serialize_frame(value, buf);
            }
        }
        Frame::Push(items) => {
            buf.put_u8(b'>');
            let len = items.len().to_string();
            buf.extend_from_slice(len.as_bytes());
            buf.extend_from_slice(b"\r\n");
            for item in items {
                serialize_frame(item, buf);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Frame, ParseError, Parser, frame_to_bytes, parse_frame, parse_streaming_sequence};
    use bytes::Bytes;

    #[test]
    fn test_parse_frame_simple_string() {
        let input = Bytes::from("+HELLO\r\nWORLD");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::SimpleString(Bytes::from("HELLO")));
        assert_eq!(rest, Bytes::from("WORLD"));
    }

    #[test]
    fn test_parse_frame_blob_error() {
        let input = Bytes::from("!5\r\nERROR\r\nREST");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::BlobError(Bytes::from("ERROR")));
        assert_eq!(rest, Bytes::from("REST"));
    }

    #[test]
    fn test_parse_frame_error() {
        let input = Bytes::from("-ERR fail\r\nLEFT");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::Error(Bytes::from("ERR fail")));
        assert_eq!(rest, Bytes::from("LEFT"));
    }

    #[test]
    fn test_parse_frame_integer() {
        let input = Bytes::from(":42\r\nTAIL");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::Integer(42));
        assert_eq!(rest, Bytes::from("TAIL"));
    }

    #[test]
    fn test_parse_frame_bulk_string() {
        let input = Bytes::from("$3\r\nfoo\r\nREST");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::BulkString(Some(Bytes::from("foo"))));
        assert_eq!(rest, Bytes::from("REST"));
        let null_input = Bytes::from("$-1\r\nAFTER");
        let (frame, rest) = parse_frame(null_input.clone()).unwrap();
        assert_eq!(frame, Frame::BulkString(None));
        assert_eq!(rest, Bytes::from("AFTER"));
    }

    #[test]
    fn test_parse_frame_null() {
        let input = Bytes::from("_\r\nLEFT");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::Null);
        assert_eq!(rest, Bytes::from("LEFT"));
    }

    #[test]
    fn test_parse_frame_double_and_special_float() {
        let input = Bytes::from(",3.5\r\nNEXT");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::Double(3.5));
        assert_eq!(rest, Bytes::from("NEXT"));
        let input_inf = Bytes::from(",inf\r\nTAIL");
        let (frame, rest) = parse_frame(input_inf.clone()).unwrap();
        assert_eq!(frame, Frame::SpecialFloat(Bytes::from("inf")));
        assert_eq!(rest, Bytes::from("TAIL"));
    }

    #[test]
    fn test_parse_frame_boolean() {
        let input_true = Bytes::from("#t\r\nXYZ");
        let (frame, rest) = parse_frame(input_true.clone()).unwrap();
        assert_eq!(frame, Frame::Boolean(true));
        assert_eq!(rest, Bytes::from("XYZ"));
        let input_false = Bytes::from("#f\r\nDONE");
        let (frame, rest) = parse_frame(input_false.clone()).unwrap();
        assert_eq!(frame, Frame::Boolean(false));
        assert_eq!(rest, Bytes::from("DONE"));
    }

    #[test]
    fn test_parse_frame_big_number() {
        let input = Bytes::from("(123456789\r\nEND");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::BigNumber(Bytes::from("123456789")));
        assert_eq!(rest, Bytes::from("END"));
    }

    #[test]
    fn test_parse_frame_verbatim_string() {
        let input = Bytes::from("=12\r\ntxt:hi there\r\nAFTER");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(
            frame,
            Frame::VerbatimString(Bytes::from("txt"), Bytes::from("hi there")) // Frame::VerbatimString {
                                                                               //     format: "txt".to_string(),
                                                                               //     content: "hi there".to_string()
                                                                               // }
        );
        assert_eq!(rest, Bytes::from("AFTER"));
    }

    #[test]
    fn test_parse_frame_array_set_push_map_attribute() {
        // Array of two bulk strings
        let input = Bytes::from("*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\nTAIL");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(
            frame,
            Frame::Array(Some(vec![
                Frame::BulkString(Some(Bytes::from("foo"))),
                Frame::BulkString(Some(Bytes::from("bar")))
            ]))
        );
        assert_eq!(rest, Bytes::from("TAIL"));
        // Null array
        let input_null = Bytes::from("*-1\r\nEND");
        let (frame, rest) = parse_frame(input_null.clone()).unwrap();
        assert_eq!(frame, Frame::Array(None));
        assert_eq!(rest, Bytes::from("END"));
        // Set of two simple strings
        let input_set = Bytes::from("~2\r\n+foo\r\n+bar\r\nTAIL");
        let (frame, rest) = parse_frame(input_set.clone()).unwrap();
        assert_eq!(
            frame,
            Frame::Set(vec![
                Frame::SimpleString(Bytes::from("foo")),
                Frame::SimpleString(Bytes::from("bar")),
            ])
        );
        assert_eq!(rest, Bytes::from("TAIL"));
        // Map of two key-value pairs
        let input_map = Bytes::from("%2\r\n+key1\r\n+val1\r\n+key2\r\n+val2\r\nTRAIL");
        let (frame, rest) = parse_frame(input_map.clone()).unwrap();
        assert_eq!(
            frame,
            Frame::Map(vec![
                (
                    Frame::SimpleString(Bytes::from("key1")),
                    Frame::SimpleString(Bytes::from("val1"))
                ),
                (
                    Frame::SimpleString(Bytes::from("key2")),
                    Frame::SimpleString(Bytes::from("val2"))
                ),
            ])
        );
        assert_eq!(rest, Bytes::from("TRAIL"));
        // Attribute
        let input_attr = Bytes::from("|1\r\n+meta\r\n+data\r\nAFTER");
        let (frame, rest) = parse_frame(input_attr.clone()).unwrap();
        assert_eq!(
            frame,
            Frame::Attribute(vec![(
                Frame::SimpleString(Bytes::from("meta")),
                Frame::SimpleString(Bytes::from("data"))
            ),])
        );
        assert_eq!(rest, Bytes::from("AFTER"));
        // Push
        let input_push = Bytes::from(">2\r\n+type\r\n:1\r\nNEXT");
        let (frame, rest) = parse_frame(input_push.clone()).unwrap();
        assert_eq!(
            frame,
            Frame::Push(vec![
                Frame::SimpleString(Bytes::from("type")),
                Frame::Integer(1),
            ])
        );
        assert_eq!(rest, Bytes::from("NEXT"));
    }

    #[test]
    fn test_parse_frame_empty_input() {
        assert!(parse_frame(Bytes::new()).is_err());
    }

    #[test]
    fn test_parse_frame_invalid_tag() {
        let input = Bytes::from("X123\r\n");
        assert!(parse_frame(input).is_err());
    }

    #[test]
    fn test_parse_frame_malformed_bulk_length() {
        let input = Bytes::from("$x\r\nfoo\r\n");
        assert!(parse_frame(input).is_err());
    }

    #[test]
    fn test_parse_frame_zero_length_bulk() {
        let input = Bytes::from("$0\r\n\r\nTAIL");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::BulkString(Some(Bytes::from(""))));
        assert_eq!(rest, Bytes::from("TAIL"));
    }

    #[test]
    fn test_parse_frame_zero_length_blob_error() {
        let input = Bytes::from("!0\r\n\r\nREST");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::BlobError(Bytes::new()));
        assert_eq!(rest, Bytes::from("REST"));
    }

    #[test]
    fn test_parse_frame_missing_crlf() {
        let input = Bytes::from(":42\nTAIL");
        assert!(parse_frame(input).is_err());
    }

    #[test]
    fn test_parse_frame_unicode_simple_string() {
        let input = Bytes::from("+こんにちは\r\nEND");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::SimpleString(Bytes::from("こんにちは")));
        assert_eq!(rest, Bytes::from("END"));
    }

    #[test]
    fn test_parse_frame_chained_frames() {
        let combined = Bytes::from("+OK\r\n:1\r\nfoo");
        let (f1, rem) = parse_frame(combined.clone()).unwrap();
        assert_eq!(f1, Frame::SimpleString(Bytes::from("OK")));
        let (f2, rem2) = parse_frame(rem).unwrap();
        assert_eq!(f2, Frame::Integer(1));
        assert_eq!(rem2, Bytes::from("foo"));
    }

    #[test]
    fn test_parse_frame_empty_array() {
        let input = Bytes::from("*0\r\nTAIL");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::Array(Some(vec![])));
        assert_eq!(rest, Bytes::from("TAIL"));
    }

    #[test]
    fn test_parse_frame_partial_array_data() {
        let input = Bytes::from("*2\r\n+OK\r\n");
        assert!(parse_frame(input).is_err());
    }

    #[test]
    fn test_parse_frame_streamed_string() {
        let input = Bytes::from("$?\r\n$5\r\nhello\r\n$0\r\n\r\nREST");
        let (frame, rem) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::StreamedStringHeader);
        let (chunk, rem2) = parse_frame(rem.clone()).unwrap();
        assert_eq!(chunk, Frame::BulkString(Some(Bytes::from("hello"))));
        let (terminator, rest) = parse_frame(rem2.clone()).unwrap();
        assert_eq!(terminator, Frame::BulkString(Some(Bytes::from(""))));
        assert_eq!(rest, Bytes::from("REST"));
    }

    #[test]
    fn test_parse_frame_streamed_blob_error() {
        let input = Bytes::from("!?\r\n!5\r\nERROR\r\nREST");
        let (frame, rem) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::StreamedBlobErrorHeader);
        let (chunk, rem2) = parse_frame(rem.clone()).unwrap();
        assert_eq!(chunk, Frame::BlobError(Bytes::from("ERROR")));
        assert_eq!(rem2, Bytes::from("REST"));
    }

    #[test]
    fn test_parse_frame_streamed_verbatim_string() {
        let input = Bytes::from("=?\r\n=9\r\ntxt:hello\r\nTAIL");
        let (frame, rem) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::StreamedVerbatimStringHeader);
        let (chunk, rest) = parse_frame(rem.clone()).unwrap();
        assert_eq!(
            chunk,
            Frame::VerbatimString(Bytes::from("txt"), Bytes::from("hello")) // Frame::VerbatimString {
                                                                            //     format: "txt".to_string(),
                                                                            //     content: "hello".to_string()
                                                                            // }
        );
        assert_eq!(rest, Bytes::from("TAIL"));
    }

    #[test]
    fn test_parse_frame_streamed_array() {
        let input = Bytes::from("*?\r\n+one\r\n+two\r\n*0\r\nEND");
        let (header, rem) = parse_frame(input.clone()).unwrap();
        assert_eq!(header, Frame::StreamedArrayHeader);
        let (item1, rem2) = parse_frame(rem.clone()).unwrap();
        assert_eq!(item1, Frame::SimpleString(Bytes::from("one")));
        let (item2, rem3) = parse_frame(rem2.clone()).unwrap();
        assert_eq!(item2, Frame::SimpleString(Bytes::from("two")));
        let (terminator, rest) = parse_frame(rem3.clone()).unwrap();
        assert_eq!(terminator, Frame::Array(Some(vec![])));
        assert_eq!(rest, Bytes::from("END"));
    }

    #[test]
    fn test_parse_frame_streamed_set_map_attr_push() {
        // Set
        let input_set = Bytes::from("~?\r\n+foo\r\n+bar\r\n~0\r\nTAIL");
        let (h_set, rem0) = parse_frame(input_set.clone()).unwrap();
        assert_eq!(h_set, Frame::StreamedSetHeader);
        let (s1, rem1) = parse_frame(rem0.clone()).unwrap();
        assert_eq!(s1, Frame::SimpleString(Bytes::from("foo")));
        let (s2, rem2) = parse_frame(rem1.clone()).unwrap();
        assert_eq!(s2, Frame::SimpleString(Bytes::from("bar")));
        let (term_set, rest_set) = parse_frame(rem2.clone()).unwrap();
        assert_eq!(term_set, Frame::Set(vec![]));
        assert_eq!(rest_set, Bytes::from("TAIL"));
        // Map
        let input_map = Bytes::from("%?\r\n+key\r\n+val\r\n%0\r\nNEXT");
        let (h_map, rem_map) = parse_frame(input_map.clone()).unwrap();
        assert_eq!(h_map, Frame::StreamedMapHeader);
        let (k, rem_map2) = parse_frame(rem_map.clone()).unwrap();
        assert_eq!(k, Frame::SimpleString(Bytes::from("key")));
        let (v, rem_map3) = parse_frame(rem_map2.clone()).unwrap();
        assert_eq!(v, Frame::SimpleString(Bytes::from("val")));
        let (term_map, rest_map4) = parse_frame(rem_map3.clone()).unwrap();
        assert_eq!(term_map, Frame::Map(vec![]));
        assert_eq!(rest_map4, Bytes::from("NEXT"));
        // Attribute
        let input_attr = Bytes::from("|?\r\n+meta\r\n+info\r\n|0\r\nMORE");
        let (h_attr, rem_attr) = parse_frame(input_attr.clone()).unwrap();
        assert_eq!(h_attr, Frame::StreamedAttributeHeader);
        let (a1, rem_attr2) = parse_frame(rem_attr.clone()).unwrap();
        assert_eq!(a1, Frame::SimpleString(Bytes::from("meta")));
        let (a2, rem_attr3) = parse_frame(rem_attr2.clone()).unwrap();
        assert_eq!(a2, Frame::SimpleString(Bytes::from("info")));
        let (term_attr, rest_attr) = parse_frame(rem_attr3.clone()).unwrap();
        assert_eq!(term_attr, Frame::Attribute(vec![]));
        assert_eq!(rest_attr, Bytes::from("MORE"));
        // Push
        let input_push = Bytes::from(">?\r\n:1\r\n:2\r\n>0\r\nEND");
        let (h_push, rem_push) = parse_frame(input_push.clone()).unwrap();
        assert_eq!(h_push, Frame::StreamedPushHeader);
        let (p1, rem_push2) = parse_frame(rem_push.clone()).unwrap();
        assert_eq!(p1, Frame::Integer(1));
        let (p2, rem_push3) = parse_frame(rem_push2.clone()).unwrap();
        assert_eq!(p2, Frame::Integer(2));
        let (term_push, rest_push) = parse_frame(rem_push3.clone()).unwrap();
        assert_eq!(term_push, Frame::Push(vec![]));
        assert_eq!(rest_push, Bytes::from("END"));
    }

    #[test]
    fn test_parse_frame_stream_terminator() {
        let input = Bytes::from(".\r\nREST");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::StreamTerminator);
        assert_eq!(rest, Bytes::from("REST"));
    }

    #[test]
    fn test_parse_frame_null_bulk_and_error() {
        let input1 = Bytes::from("!-1\r\nTAIL");
        let (f1, r1) = parse_frame(input1.clone()).unwrap();
        assert_eq!(f1, Frame::BlobError(Bytes::new()));
        assert_eq!(r1, Bytes::from("TAIL"));
        let input2 = Bytes::from("=-1\r\nTAIL");
        let (f2, r2) = parse_frame(input2.clone()).unwrap();
        assert_eq!(f2, Frame::VerbatimString(Bytes::new(), Bytes::new()));
        assert_eq!(r2, Bytes::from("TAIL"));
    }

    #[test]
    fn test_parse_frame_special_float_nan() {
        let input = Bytes::from(",nan\r\nTAIL");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::SpecialFloat(Bytes::from("nan")));
        assert_eq!(rest, Bytes::from("TAIL"));
    }

    #[test]
    fn test_parse_frame_big_number_zero() {
        let input = Bytes::from("(0\r\nEND");
        let (frame, rest) = parse_frame(input.clone()).unwrap();
        assert_eq!(frame, Frame::BigNumber(Bytes::from("0")));
        assert_eq!(rest, Bytes::from("END"));
    }

    #[test]
    fn test_parse_frame_collection_empty() {
        let input_push = Bytes::from(">0\r\nTAIL");
        let (f_push, r_push) = parse_frame(input_push.clone()).unwrap();
        assert_eq!(f_push, Frame::Push(vec![]));
        assert_eq!(r_push, Bytes::from("TAIL"));
        let input_attr = Bytes::from("|0\r\nAFTER");
        let (f_attr, r_attr) = parse_frame(input_attr.clone()).unwrap();
        assert_eq!(f_attr, Frame::Attribute(vec![]));
        assert_eq!(r_attr, Bytes::from("AFTER"));
        let input_map = Bytes::from("%0\r\nEND");
        let (f_map, r_map) = parse_frame(input_map.clone()).unwrap();
        assert_eq!(f_map, Frame::Map(vec![]));
        assert_eq!(r_map, Bytes::from("END"));
        let input_set = Bytes::from("~0\r\nDONE");
        let (f_set, r_set) = parse_frame(input_set.clone()).unwrap();
        assert_eq!(f_set, Frame::Set(vec![]));
        assert_eq!(r_set, Bytes::from("DONE"));
        let input_arr = Bytes::from("*-1\r\nFIN");
        let (f_arr, r_arr) = parse_frame(input_arr.clone()).unwrap();
        assert_eq!(f_arr, Frame::Array(None));
        assert_eq!(r_arr, Bytes::from("FIN"));
    }

    // Round-trip tests for serialization and parsing

    #[test]
    fn test_roundtrip_simple_string() {
        let original = Bytes::from("+hello\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_error() {
        let original = Bytes::from("-ERR error message\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_integer() {
        let original = Bytes::from(":12345\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_bulk_string() {
        let original = Bytes::from("$5\r\nhello\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);

        // Test null bulk string
        let original_null = Bytes::from("$-1\r\n");
        let (frame_null, _) = parse_frame(original_null.clone()).unwrap();
        let serialized_null = frame_to_bytes(&frame_null);
        assert_eq!(original_null, serialized_null);

        let (reparsed_null, _) = parse_frame(serialized_null).unwrap();
        assert_eq!(frame_null, reparsed_null);
    }

    #[test]
    fn test_roundtrip_blob_error() {
        let original = Bytes::from("!5\r\nerror\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_null() {
        let original = Bytes::from("_\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_double() {
        let original = Bytes::from(",3.14159\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);

        // Note: The exact string representation of floating point numbers might differ
        // between parsing and serializing due to formatting differences
        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_special_float() {
        let original = Bytes::from(",inf\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_boolean() {
        let original_true = Bytes::from("#t\r\n");
        let (frame_true, _) = parse_frame(original_true.clone()).unwrap();
        let serialized_true = frame_to_bytes(&frame_true);
        assert_eq!(original_true, serialized_true);

        let (reparsed_true, _) = parse_frame(serialized_true).unwrap();
        assert_eq!(frame_true, reparsed_true);

        let original_false = Bytes::from("#f\r\n");
        let (frame_false, _) = parse_frame(original_false.clone()).unwrap();
        let serialized_false = frame_to_bytes(&frame_false);
        assert_eq!(original_false, serialized_false);

        let (reparsed_false, _) = parse_frame(serialized_false).unwrap();
        assert_eq!(frame_false, reparsed_false);
    }

    #[test]
    fn test_roundtrip_big_number() {
        let original = Bytes::from("(12345678901234567890\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_verbatim_string() {
        let original = Bytes::from("=10\r\ntxt:hello!\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_array() {
        let original = Bytes::from("*2\r\n+hello\r\n:123\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);

        // Test null array
        let original_null = Bytes::from("*-1\r\n");
        let (frame_null, _) = parse_frame(original_null.clone()).unwrap();
        let serialized_null = frame_to_bytes(&frame_null);
        assert_eq!(original_null, serialized_null);

        let (reparsed_null, _) = parse_frame(serialized_null).unwrap();
        assert_eq!(frame_null, reparsed_null);
    }

    #[test]
    fn test_roundtrip_set() {
        let original = Bytes::from("~2\r\n+one\r\n+two\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_map() {
        let original = Bytes::from("%2\r\n+key1\r\n+val1\r\n+key2\r\n+val2\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_attribute() {
        let original = Bytes::from("|1\r\n+key\r\n+val\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_push() {
        let original = Bytes::from(">2\r\n+msg\r\n+data\r\n");
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);
        assert_eq!(original, serialized);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_roundtrip_streaming_headers() {
        let headers = [
            ("$?\r\n", Frame::StreamedStringHeader),
            ("!?\r\n", Frame::StreamedBlobErrorHeader),
            ("=?\r\n", Frame::StreamedVerbatimStringHeader),
            ("*?\r\n", Frame::StreamedArrayHeader),
            ("~?\r\n", Frame::StreamedSetHeader),
            ("%?\r\n", Frame::StreamedMapHeader),
            ("|?\r\n", Frame::StreamedAttributeHeader),
            (">?\r\n", Frame::StreamedPushHeader),
            (".\r\n", Frame::StreamTerminator),
        ];

        for (original_str, expected_frame) in headers {
            let original = Bytes::from(original_str);
            let (frame, _) = parse_frame(original.clone()).unwrap();
            assert_eq!(frame, expected_frame);

            let serialized = frame_to_bytes(&frame);
            assert_eq!(original, serialized);

            let (reparsed, _) = parse_frame(serialized).unwrap();
            assert_eq!(frame, reparsed);
        }
    }

    #[test]
    fn test_roundtrip_streaming_chunks() {
        let chunks = [
            (
                ";4\r\nHell\r\n",
                Frame::StreamedStringChunk(Bytes::from("Hell")),
            ),
            (
                ";5\r\no wor\r\n",
                Frame::StreamedStringChunk(Bytes::from("o wor")),
            ),
            (";1\r\nd\r\n", Frame::StreamedStringChunk(Bytes::from("d"))),
            (";0\r\n\r\n", Frame::StreamedStringChunk(Bytes::new())),
            (
                ";11\r\nHello World\r\n",
                Frame::StreamedStringChunk(Bytes::from("Hello World")),
            ),
        ];

        for (original_str, expected_frame) in chunks {
            let original = Bytes::from(original_str);
            let (frame, rest) = parse_frame(original.clone()).unwrap();
            assert_eq!(frame, expected_frame);
            assert!(rest.is_empty());

            let serialized = frame_to_bytes(&frame);
            assert_eq!(original, serialized);

            let (reparsed, _) = parse_frame(serialized).unwrap();
            assert_eq!(frame, reparsed);
        }
    }

    #[test]
    fn test_streaming_chunks_edge_cases() {
        // Test incomplete chunk (missing data)
        let data = Bytes::from(";4\r\nHel");
        let result = parse_frame(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test incomplete chunk (missing CRLF)
        let data = Bytes::from(";4\r\nHell");
        let result = parse_frame(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test invalid length format
        let data = Bytes::from(";abc\r\ndata\r\n");
        let result = parse_frame(data);
        assert!(matches!(result, Err(ParseError::BadLength)));

        // Test negative length
        let data = Bytes::from(";-1\r\ndata\r\n");
        let result = parse_frame(data);
        assert!(matches!(result, Err(ParseError::BadLength)));

        // Test length mismatch (length says 5 but only 4 bytes)
        let data = Bytes::from(";5\r\nHell\r\n");
        let result = parse_frame(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test zero-length chunk without trailing CRLF returns Incomplete
        let data = Bytes::from(";0\r\n");
        let result = parse_frame(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test binary data in chunk
        let binary_data = b"\x00\x01\x02\x03\xFF";
        let mut chunk_data = Vec::new();
        chunk_data.extend_from_slice(b";5\r\n");
        chunk_data.extend_from_slice(binary_data);
        chunk_data.extend_from_slice(b"\r\n");
        let data = Bytes::from(chunk_data);
        let result = parse_frame(data);
        assert!(result.is_ok());
        let (frame, _) = result.unwrap();
        if let Frame::StreamedStringChunk(chunk) = frame {
            assert_eq!(chunk.as_ref(), binary_data);
        }
    }

    #[test]
    fn test_roundtrip_streaming_sequences() {
        // Test streaming string roundtrip
        let streaming_string = Frame::StreamedString(vec![
            Bytes::from("Hell"),
            Bytes::from("o wor"),
            Bytes::from("ld"),
        ]);
        let serialized = frame_to_bytes(&streaming_string);
        let expected = "$?\r\n;4\r\nHell\r\n;5\r\no wor\r\n;2\r\nld\r\n;0\r\n\r\n";
        assert_eq!(serialized, Bytes::from(expected));

        let (parsed, _) = parse_streaming_sequence(serialized).unwrap();
        assert_eq!(parsed, streaming_string);

        // Test streaming array roundtrip
        let streaming_array = Frame::StreamedArray(vec![
            Frame::SimpleString(Bytes::from("hello")),
            Frame::Integer(42),
            Frame::Boolean(true),
        ]);
        let serialized = frame_to_bytes(&streaming_array);
        let (parsed, _) = parse_streaming_sequence(serialized.clone()).unwrap();
        assert_eq!(parsed, streaming_array);

        // Test streaming map roundtrip
        let streaming_map = Frame::StreamedMap(vec![
            (
                Frame::SimpleString(Bytes::from("key1")),
                Frame::SimpleString(Bytes::from("val1")),
            ),
            (
                Frame::SimpleString(Bytes::from("key2")),
                Frame::Integer(123),
            ),
        ]);
        let serialized = frame_to_bytes(&streaming_map);
        let (parsed, _) = parse_streaming_sequence(serialized.clone()).unwrap();
        assert_eq!(parsed, streaming_map);

        // Test empty streaming string
        let empty_streaming = Frame::StreamedString(vec![]);
        let serialized = frame_to_bytes(&empty_streaming);
        let expected = "$?\r\n;0\r\n\r\n";
        assert_eq!(serialized, Bytes::from(expected));
        let (parsed, _) = parse_streaming_sequence(serialized).unwrap();
        assert_eq!(parsed, empty_streaming);

        // Test streaming set roundtrip
        let streaming_set = Frame::StreamedSet(vec![
            Frame::SimpleString(Bytes::from("apple")),
            Frame::SimpleString(Bytes::from("banana")),
            Frame::Integer(42),
        ]);
        let serialized = frame_to_bytes(&streaming_set);
        let (parsed, _) = parse_streaming_sequence(serialized.clone()).unwrap();
        assert_eq!(parsed, streaming_set);

        // Test streaming attribute roundtrip
        let streaming_attribute = Frame::StreamedAttribute(vec![
            (
                Frame::SimpleString(Bytes::from("trace-id")),
                Frame::SimpleString(Bytes::from("abc123")),
            ),
            (
                Frame::SimpleString(Bytes::from("span-id")),
                Frame::SimpleString(Bytes::from("def456")),
            ),
        ]);
        let serialized = frame_to_bytes(&streaming_attribute);
        let (parsed, _) = parse_streaming_sequence(serialized.clone()).unwrap();
        assert_eq!(parsed, streaming_attribute);

        // Test streaming push roundtrip
        let streaming_push = Frame::StreamedPush(vec![
            Frame::SimpleString(Bytes::from("pubsub")),
            Frame::SimpleString(Bytes::from("channel1")),
            Frame::SimpleString(Bytes::from("message data")),
        ]);
        let serialized = frame_to_bytes(&streaming_push);
        let (parsed, _) = parse_streaming_sequence(serialized.clone()).unwrap();
        assert_eq!(parsed, streaming_push);

        // Test empty streaming containers
        let empty_array = Frame::StreamedArray(vec![]);
        let serialized = frame_to_bytes(&empty_array);
        let (parsed, _) = parse_streaming_sequence(serialized).unwrap();
        assert_eq!(parsed, empty_array);

        let empty_set = Frame::StreamedSet(vec![]);
        let serialized = frame_to_bytes(&empty_set);
        let (parsed, _) = parse_streaming_sequence(serialized).unwrap();
        assert_eq!(parsed, empty_set);
    }

    #[test]
    fn test_streaming_sequences_edge_cases() {
        // Test incomplete streaming string (missing zero-length terminator)
        let data = Bytes::from("$?\r\n;4\r\nHell\r\n;5\r\no wor\r\n");
        let result = parse_streaming_sequence(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test malformed chunk in streaming sequence
        let data = Bytes::from("$?\r\n;abc\r\nHell\r\n;0\r\n");
        let result = parse_streaming_sequence(data);
        assert!(matches!(result, Err(ParseError::BadLength)));

        // Test streaming array with incomplete terminator
        let data = Bytes::from("*?\r\n+hello\r\n:42\r\n");
        let result = parse_streaming_sequence(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test mixed streaming and non-streaming content
        let data = Bytes::from("*?\r\n+hello\r\n*2\r\n:1\r\n:2\r\n.\r\n");
        let result = parse_streaming_sequence(data);
        assert!(result.is_ok());
        let (frame, _) = result.unwrap();
        if let Frame::StreamedArray(items) = frame {
            assert_eq!(items.len(), 2);
            assert!(matches!(items[0], Frame::SimpleString(_)));
            assert!(matches!(items[1], Frame::Array(_)));
        }

        // Test empty streaming containers
        let data = Bytes::from("*?\r\n.\r\n");
        let result = parse_streaming_sequence(data);
        assert!(result.is_ok());
        let (frame, _) = result.unwrap();
        if let Frame::StreamedArray(items) = frame {
            assert!(items.is_empty());
        }

        // Test streaming map with odd number of elements (should work)
        let data = Bytes::from("%?\r\n+key1\r\n+val1\r\n+orphan\r\n.\r\n");
        let result = parse_streaming_sequence(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test non-streaming frame passed to parse_streaming_sequence
        let data = Bytes::from("+simple\r\n");
        let result = parse_streaming_sequence(data);
        assert!(result.is_ok());
        let (frame, _) = result.unwrap();
        assert!(matches!(frame, Frame::SimpleString(_)));

        // Test extremely large chunk size (should fail gracefully)
        let data = Bytes::from(";999999999999999999\r\ndata\r\n");
        let result = parse_frame(data);
        // The parsing might succeed but fail later when trying to read the data
        // Let's check what actually happens and accept either BadLength or Incomplete
        match &result {
            Err(ParseError::BadLength) => {}  // Expected
            Err(ParseError::Incomplete) => {} // Also acceptable - might not have enough data for huge chunk
            Err(e) => panic!("Got unexpected error type: {e:?}"),
            Ok(_) => panic!("Large chunk size should fail"),
        }

        // Test streaming string with non-chunk frame mixed in
        let data = Bytes::from("$?\r\n+invalid\r\n;0\r\n");
        let result = parse_streaming_sequence(data);
        assert!(matches!(result, Err(ParseError::InvalidFormat)));

        // Test streaming sequence with corrupted terminator
        let data = Bytes::from("*?\r\n+hello\r\n.corrupted\r\n");
        let result = parse_streaming_sequence(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test empty input to parse_streaming_sequence
        let data = Bytes::new();
        let result = parse_streaming_sequence(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));

        // Test streaming sequence with partial frame at end
        let data = Bytes::from("*?\r\n+hello\r\n$5\r\nwo");
        let result = parse_streaming_sequence(data);
        assert!(matches!(result, Err(ParseError::Incomplete)));
    }

    #[test]
    fn test_roundtrip_nested_structures() {
        // Test a complex nested structure
        let original = Bytes::from(
            "*3\r\n+hello\r\n%2\r\n+key1\r\n:123\r\n+key2\r\n~1\r\n+item\r\n|1\r\n+meta\r\n+data\r\n",
        );
        let (frame, _) = parse_frame(original.clone()).unwrap();
        let serialized = frame_to_bytes(&frame);

        let (reparsed, _) = parse_frame(serialized).unwrap();
        assert_eq!(frame, reparsed);
    }

    #[test]
    fn test_zero_length_bulk_string_requires_trailing_crlf() {
        // Complete: $0\r\n\r\n
        let input = Bytes::from("$0\r\n\r\nTAIL");
        let (frame, rest) = parse_frame(input).unwrap();
        assert_eq!(frame, Frame::BulkString(Some(Bytes::new())));
        assert_eq!(rest, Bytes::from("TAIL"));

        // Incomplete: $0\r\n with no trailing data
        let input = Bytes::from("$0\r\n");
        assert_eq!(parse_frame(input), Err(ParseError::Incomplete));

        // Incomplete: $0\r\n with only one byte
        let input = Bytes::from("$0\r\n\r");
        assert_eq!(parse_frame(input), Err(ParseError::Incomplete));

        // Invalid: $0\r\n followed by non-CRLF
        let input = Bytes::from("$0\r\nXY");
        assert_eq!(parse_frame(input), Err(ParseError::InvalidFormat));
    }

    #[test]
    fn test_zero_length_streamed_chunk_requires_trailing_crlf() {
        // Complete: ;0\r\n\r\n
        let input = Bytes::from(";0\r\n\r\nTAIL");
        let (frame, rest) = parse_frame(input).unwrap();
        assert_eq!(frame, Frame::StreamedStringChunk(Bytes::new()));
        assert_eq!(rest, Bytes::from("TAIL"));

        // Incomplete: ;0\r\n with no trailing data
        let input = Bytes::from(";0\r\n");
        assert_eq!(parse_frame(input), Err(ParseError::Incomplete));

        // Invalid: ;0\r\n followed by non-CRLF
        let input = Bytes::from(";0\r\nXY");
        assert_eq!(parse_frame(input), Err(ParseError::InvalidFormat));
    }

    #[test]
    fn test_integer_overflow_returns_overflow_error() {
        // One past i64::MAX
        let input = Bytes::from(":9223372036854775808\r\n");
        assert_eq!(parse_frame(input), Err(ParseError::Overflow));

        // i64::MAX should succeed
        let input = Bytes::from(":9223372036854775807\r\n");
        let (frame, _) = parse_frame(input).unwrap();
        assert_eq!(frame, Frame::Integer(i64::MAX));

        // i64::MIN should succeed
        let input = Bytes::from(":-9223372036854775808\r\n");
        let (frame, _) = parse_frame(input).unwrap();
        assert_eq!(frame, Frame::Integer(i64::MIN));
    }

    #[test]
    fn test_parser_propagates_errors() {
        let mut parser = Parser::new();
        parser.feed(Bytes::from("XINVALID\r\n"));
        let result = parser.next_frame();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ParseError::InvalidTag(b'X'));
    }

    #[test]
    fn test_parser_returns_ok_none_for_incomplete() {
        let mut parser = Parser::new();
        parser.feed(Bytes::from("+HELL"));
        assert_eq!(parser.next_frame().unwrap(), None);
    }

    #[test]
    fn test_integer_negative_overflow() {
        // One past i64::MIN
        assert!(parse_frame(Bytes::from(":-9223372036854775809\r\n")).is_err());
    }

    #[test]
    fn test_nonempty_bulk_malformed_terminator() {
        // Not enough data after payload
        assert_eq!(
            parse_frame(Bytes::from("$3\r\nfoo")),
            Err(ParseError::Incomplete)
        );
        // Only one byte after payload
        assert_eq!(
            parse_frame(Bytes::from("$3\r\nfooX")),
            Err(ParseError::Incomplete)
        );
        // Two bytes present but wrong
        assert_eq!(
            parse_frame(Bytes::from("$3\r\nfooXY")),
            Err(ParseError::InvalidFormat)
        );
    }

    #[test]
    fn test_blob_error_malformed_terminator() {
        assert_eq!(
            parse_frame(Bytes::from("!3\r\nerr")),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            parse_frame(Bytes::from("!3\r\nerrXY")),
            Err(ParseError::InvalidFormat)
        );
    }

    #[test]
    fn test_verbatim_string_malformed_terminator() {
        assert_eq!(
            parse_frame(Bytes::from("=8\r\ntxt:data")),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            parse_frame(Bytes::from("=8\r\ntxt:dataXY")),
            Err(ParseError::InvalidFormat)
        );
    }

    #[test]
    fn test_streamed_chunk_malformed_terminator() {
        assert_eq!(
            parse_frame(Bytes::from(";3\r\nabc")),
            Err(ParseError::Incomplete)
        );
        assert_eq!(
            parse_frame(Bytes::from(";3\r\nabcXY")),
            Err(ParseError::InvalidFormat)
        );
    }

    #[test]
    fn test_bulk_string_size_limit() {
        // Over MAX_BULK_STRING_SIZE (512 MB)
        assert_eq!(
            parse_frame(Bytes::from("$536870913\r\n")),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn test_blob_error_size_limit() {
        assert_eq!(
            parse_frame(Bytes::from("!536870913\r\n")),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn test_verbatim_string_size_limit() {
        assert_eq!(
            parse_frame(Bytes::from("=536870913\r\n")),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn test_streamed_chunk_size_limit() {
        assert_eq!(
            parse_frame(Bytes::from(";536870913\r\n")),
            Err(ParseError::BadLength)
        );
    }

    #[test]
    fn test_invalid_double() {
        assert_eq!(
            parse_frame(Bytes::from(",foo\r\n")),
            Err(ParseError::InvalidFormat)
        );
    }

    #[test]
    fn test_invalid_boolean() {
        assert_eq!(
            parse_frame(Bytes::from("#\r\n")),
            Err(ParseError::InvalidBoolean)
        );
        assert_eq!(
            parse_frame(Bytes::from("#true\r\n")),
            Err(ParseError::InvalidBoolean)
        );
    }

    #[test]
    fn test_parser_clears_buffer_on_error() {
        let mut parser = Parser::new();
        parser.feed(Bytes::from("X\r\n"));
        assert_eq!(parser.next_frame(), Err(ParseError::InvalidTag(b'X')));
        assert_eq!(parser.buffered_bytes(), 0);
    }

    #[test]
    fn test_parser_recovers_after_error() {
        let mut parser = Parser::new();
        parser.feed(Bytes::from("X\r\n"));
        assert!(parser.next_frame().is_err());
        assert_eq!(parser.buffered_bytes(), 0);

        parser.feed(Bytes::from("+OK\r\n"));
        let frame = parser.next_frame().unwrap().unwrap();
        assert_eq!(frame, Frame::SimpleString(Bytes::from("OK")));
    }
}
