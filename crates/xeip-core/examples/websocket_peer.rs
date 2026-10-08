//! Development-only RFC 6455 WebSocket client peer for the XEIP relay `/ws`
//! endpoint (issue #7). Transport code stays outside xeip-core, so this is an
//! example rather than a library module. It is a dependency-free client that
//! interoperates with `services/relay/websocket.mjs` and the contract in
//! `spec/transports/websocket.md`: masked client text frames, unmasked server
//! frames, fragmentation, ping/pong, the close handshake and a bounded message
//! size. It is a local demonstrator, not a production WebSocket stack.
use std::collections::VecDeque;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use xeip_core::Envelope;

/// Each frame and each reassembled message is bounded to 128 KiB, matching the
/// reference server.
const MAX_FRAME: usize = 128 * 1024;
/// Control frames (ping/pong/close) must be final and at most 125 bytes.
const MAX_CONTROL_PAYLOAD: usize = 125;
/// Cap the HTTP upgrade response so a hostile peer cannot exhaust memory.
const MAX_HEADER: usize = 16 * 1024;

/// The fixed RFC 6455 handshake GUID.
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xa;

const CLOSE_NORMAL: u16 = 1000;
const CLOSE_PROTOCOL: u16 = 1002;
const CLOSE_UNSUPPORTED: u16 = 1003;
const CLOSE_INVALID_PAYLOAD: u16 = 1007;
const CLOSE_TOO_BIG: u16 = 1009;

/// A protocol violation detected while parsing a server frame. The `code` is
/// the RFC 6455 close code the client should echo back to the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WsError {
    code: u16,
    reason: &'static str,
}

impl WsError {
    fn protocol(reason: &'static str) -> Self {
        Self {
            code: CLOSE_PROTOCOL,
            reason,
        }
    }

    fn unsupported(reason: &'static str) -> Self {
        Self {
            code: CLOSE_UNSUPPORTED,
            reason,
        }
    }

    fn invalid_payload(reason: &'static str) -> Self {
        Self {
            code: CLOSE_INVALID_PAYLOAD,
            reason,
        }
    }

    fn too_big(reason: &'static str) -> Self {
        Self {
            code: CLOSE_TOO_BIG,
            reason,
        }
    }
}

/// A decoded WebSocket message. Text messages are reassembled and UTF-8
/// validated; control frames are surfaced so the caller can react to them.
#[derive(Debug, PartialEq, Eq)]
enum Message {
    Text(String),
    Close { code: u16, reason: String },
    Ping(Vec<u8>),
    Pong(Vec<u8>),
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// Incremental frame reader. It expects unmasked server frames by default and
/// rejects masked ones; `expect_mask` is only enabled by tests to round-trip
/// the client encoder. Fragmented text messages are reassembled here.
struct FrameDecoder {
    buffer: Vec<u8>,
    expect_mask: bool,
    fragments: Vec<u8>,
    fragment_opcode: Option<u8>,
}

impl FrameDecoder {
    fn new(expect_mask: bool) -> Self {
        Self {
            buffer: Vec::new(),
            expect_mask,
            fragments: Vec::new(),
            fragment_opcode: None,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<Vec<Message>, WsError> {
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        while let Some(frame) = self.read_frame()? {
            self.handle_frame(frame, &mut events)?;
        }
        Ok(events)
    }

    fn read_frame(&mut self) -> Result<Option<Frame>, WsError> {
        if self.buffer.len() < 2 {
            return Ok(None);
        }
        let first = self.buffer[0];
        let second = self.buffer[1];
        if first & 0x70 != 0 {
            return Err(WsError::protocol("reserved bits set"));
        }
        let fin = first & 0x80 != 0;
        let opcode = first & 0x0f;
        let masked = second & 0x80 != 0;
        if masked != self.expect_mask {
            return Err(WsError::protocol(if self.expect_mask {
                "client frames must be masked"
            } else {
                "server frames must not be masked"
            }));
        }
        let mut length = usize::from(second & 0x7f);
        let mut offset = 2;
        if length == 126 {
            if self.buffer.len() < offset + 2 {
                return Ok(None);
            }
            length = usize::from(u16::from_be_bytes([
                self.buffer[offset],
                self.buffer[offset + 1],
            ]));
            offset += 2;
        } else if length == 127 {
            if self.buffer.len() < offset + 8 {
                return Ok(None);
            }
            let mut wide = [0u8; 8];
            wide.copy_from_slice(&self.buffer[offset..offset + 8]);
            let wide = u64::from_be_bytes(wide);
            if wide > MAX_FRAME as u64 {
                return Err(WsError::too_big("frame exceeds limit"));
            }
            length = wide as usize;
            offset += 8;
        }
        let is_control = opcode >= 0x8;
        if is_control {
            if length > MAX_CONTROL_PAYLOAD || !fin {
                return Err(WsError::protocol("invalid control frame"));
            }
        } else if length > MAX_FRAME {
            return Err(WsError::too_big("frame exceeds limit"));
        }
        let mask = if self.expect_mask {
            if self.buffer.len() < offset + 4 {
                return Ok(None);
            }
            let mut mask = [0u8; 4];
            mask.copy_from_slice(&self.buffer[offset..offset + 4]);
            offset += 4;
            Some(mask)
        } else {
            None
        };
        if self.buffer.len() < offset + length {
            return Ok(None);
        }
        let mut payload = self.buffer[offset..offset + length].to_vec();
        if let Some(mask) = mask {
            apply_mask(&mut payload, &mask);
        }
        self.buffer.drain(..offset + length);
        Ok(Some(Frame {
            fin,
            opcode,
            payload,
        }))
    }

    fn handle_frame(&mut self, frame: Frame, events: &mut Vec<Message>) -> Result<(), WsError> {
        match frame.opcode {
            OP_CLOSE => {
                if frame.payload.len() == 1 {
                    return Err(WsError::protocol("invalid close payload"));
                }
                let code = if frame.payload.len() >= 2 {
                    u16::from_be_bytes([frame.payload[0], frame.payload[1]])
                } else {
                    CLOSE_NORMAL
                };
                let reason = if frame.payload.len() >= 2 {
                    String::from_utf8(frame.payload[2..].to_vec())
                        .map_err(|_| WsError::invalid_payload("invalid close reason"))?
                } else {
                    String::new()
                };
                events.push(Message::Close { code, reason });
            }
            OP_PING => events.push(Message::Ping(frame.payload)),
            OP_PONG => events.push(Message::Pong(frame.payload)),
            OP_BINARY => return Err(WsError::unsupported("binary messages are not supported")),
            OP_TEXT => {
                if self.fragment_opcode.is_some() {
                    return Err(WsError::protocol("nested fragmented message"));
                }
                if frame.fin {
                    let text = String::from_utf8(frame.payload)
                        .map_err(|_| WsError::invalid_payload("invalid UTF-8 text message"))?;
                    events.push(Message::Text(text));
                } else {
                    self.fragment_opcode = Some(OP_TEXT);
                    self.fragments = frame.payload;
                    if self.fragments.len() > MAX_FRAME {
                        return Err(WsError::too_big("message exceeds limit"));
                    }
                }
            }
            OP_CONTINUATION => {
                if self.fragment_opcode.is_none() {
                    return Err(WsError::protocol("unexpected continuation frame"));
                }
                self.fragments.extend_from_slice(&frame.payload);
                if self.fragments.len() > MAX_FRAME {
                    return Err(WsError::too_big("message exceeds limit"));
                }
                if frame.fin {
                    self.fragment_opcode = None;
                    let text = String::from_utf8(std::mem::take(&mut self.fragments))
                        .map_err(|_| WsError::invalid_payload("invalid UTF-8 text message"))?;
                    events.push(Message::Text(text));
                }
            }
            _ => return Err(WsError::protocol("unknown opcode")),
        }
        Ok(())
    }
}

/// XORs a payload with a repeating 4-byte mask. Masking is an involution, so
/// the same call both masks and unmasks.
fn apply_mask(payload: &mut [u8], mask: &[u8; 4]) {
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index & 3];
    }
}

/// Encodes a single client frame. Client frames are always masked.
fn encode_frame(opcode: u8, payload: &[u8], fin: bool, mask: [u8; 4]) -> Vec<u8> {
    let length = payload.len();
    let mut frame = Vec::with_capacity(length + 14);
    frame.push(if fin { 0x80 } else { 0x00 } | opcode);
    if length <= 125 {
        frame.push(0x80 | length as u8);
    } else if length <= usize::from(u16::MAX) {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(length as u64).to_be_bytes());
    }
    frame.extend_from_slice(&mask);
    let start = frame.len();
    frame.extend_from_slice(payload);
    apply_mask(&mut frame[start..], &mask);
    frame
}

/// Standard base64 with padding, as required by `Sec-WebSocket-Key`/`-Accept`.
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = u32::from(chunk[0]);
        let second = u32::from(*chunk.get(1).unwrap_or(&0));
        let third = u32::from(*chunk.get(2).unwrap_or(&0));
        let packed = (first << 16) | (second << 8) | third;
        out.push(BASE64[((packed >> 18) & 63) as usize] as char);
        out.push(BASE64[((packed >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64[((packed >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64[(packed & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Minimal local SHA-1 used ONLY to verify the RFC 6455 handshake accept
/// value. This is protocol framing, not identity cryptography: WebSocket
/// handshakes are not a security boundary, and nothing here should be used for
/// signatures or message authentication. Kept private so it cannot leak into
/// the transport-neutral core.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_length = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut words = [0u32; 80];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            let start = index * 4;
            *word = u32::from_be_bytes([
                chunk[start],
                chunk[start + 1],
                chunk[start + 2],
                chunk[start + 3],
            ]);
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (mix, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(mix)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
    }

    let mut digest = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// RFC 6455 `Sec-WebSocket-Accept` for a client key.
fn websocket_accept(key: &str) -> String {
    let mut data = String::with_capacity(key.len() + GUID.len());
    data.push_str(key);
    data.push_str(GUID);
    base64_encode(&sha1(data.as_bytes()))
}

/// Fallback entropy for platforms without `/dev/urandom`. The handshake key
/// only needs to be unpredictable enough to avoid caching collisions, so a
/// time/ counter-seeded xorshift is adequate for a loopback demonstrator.
fn fallback_bytes(key: &mut [u8; 16]) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let mut state = nanos ^ COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    for chunk in key.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

fn random_bytes() -> [u8; 16] {
    let mut key = [0u8; 16];
    if let Ok(mut file) = File::open("/dev/urandom") {
        if file.read_exact(&mut key).is_ok() {
            return key;
        }
    }
    fallback_bytes(&mut key);
    key
}

fn random_mask() -> [u8; 4] {
    let bytes = random_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_headers(stream: &mut TcpStream) -> io::Result<(String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed during handshake",
            ));
        }
        buffer.extend_from_slice(&chunk[..count]);
        if buffer.len() > MAX_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "handshake headers exceed 16 KiB",
            ));
        }
        if let Some(position) = find_header_end(&buffer) {
            let head = String::from_utf8(buffer[..position].to_vec()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "handshake headers are not UTF-8",
                )
            })?;
            let rest = buffer[position + 4..].to_vec();
            return Ok((head, rest));
        }
    }
}

/// One upgraded connection and its pending decoded messages.
struct WebSocket {
    stream: TcpStream,
    decoder: FrameDecoder,
    pending: VecDeque<Message>,
    close_sent: bool,
}

impl WebSocket {
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        let frame = encode_frame(opcode, payload, true, random_mask());
        self.stream.write_all(&frame)
    }

    fn send_text(&mut self, text: &str) -> io::Result<()> {
        self.send_frame(OP_TEXT, text.as_bytes())
    }

    /// Sends one text message split across masked fragments. `chunk` is the
    /// maximum fragment size and is floored at one byte.
    fn send_text_fragmented(&mut self, text: &str, chunk: usize) -> io::Result<()> {
        let bytes = text.as_bytes();
        if bytes.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "message exceeds 128 KiB",
            ));
        }
        let chunk = chunk.max(1);
        let mut parts = bytes.chunks(chunk).peekable();
        let mut first = true;
        while let Some(part) = parts.next() {
            let fin = parts.peek().is_none();
            let opcode = if first { OP_TEXT } else { OP_CONTINUATION };
            first = false;
            let frame = encode_frame(opcode, part, fin, random_mask());
            self.stream.write_all(&frame)?;
        }
        if first {
            // Empty message: a single final text frame.
            self.send_frame(OP_TEXT, &[])?;
        }
        Ok(())
    }

    /// Replies to a server protocol ping.
    fn pong(&mut self, payload: &[u8]) -> io::Result<()> {
        self.send_frame(OP_PONG, payload)
    }

    fn send_close(&mut self, code: u16, reason: &str) -> io::Result<()> {
        if self.close_sent {
            return Ok(());
        }
        self.close_sent = true;
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        let bytes = reason.as_bytes();
        let take = bytes.len().min(MAX_CONTROL_PAYLOAD - 2);
        payload.extend_from_slice(&bytes[..take]);
        self.send_frame(OP_CLOSE, &payload)
    }

    /// Initiates the close handshake and half-closes the write side.
    fn close(&mut self, code: u16, reason: &str) -> io::Result<()> {
        self.send_close(code, reason)?;
        self.stream.flush()?;
        self.stream.shutdown(Shutdown::Write).ok();
        Ok(())
    }

    /// Returns the next data or control message. Incoming pings are surfaced to
    /// the caller (which should call [`WebSocket::pong`]); an incoming close is
    /// echoed once so the handshake completes.
    fn read_message(&mut self) -> io::Result<Message> {
        loop {
            if let Some(message) = self.pending.pop_front() {
                if let Message::Close { code, .. } = &message {
                    self.send_close(*code, "")?;
                }
                return Ok(message);
            }
            let mut buffer = [0u8; 8192];
            let count = self.stream.read(&mut buffer)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "websocket closed by peer",
                ));
            }
            match self.decoder.push(&buffer[..count]) {
                Ok(events) => self.pending.extend(events),
                Err(error) => {
                    let _ = self.close(error.code, error.reason);
                    return Err(io::Error::new(io::ErrorKind::InvalidData, error.reason));
                }
            }
        }
    }

    /// Sends a `subscribe` control frame. `after` is the optional local
    /// delivery resume cursor from `spec/local-delivery.md`.
    fn subscribe(&mut self, session: &str, entity: &str, after: Option<u64>) -> io::Result<()> {
        let mut value = serde_json::json!({
            "type": "subscribe",
            "session": session,
            "entity": entity,
        });
        if let Some(after) = after {
            value["after"] = serde_json::json!(after);
        }
        self.send_text(&value.to_string())
    }

    /// Sends a `send` control frame carrying one unchanged XEIP envelope. The
    /// JSON control object is fragmented to exercise the send path.
    fn send_envelope(&mut self, message: &Envelope) -> io::Result<()> {
        let value = serde_json::json!({ "type": "send", "message": message });
        self.send_text_fragmented(&value.to_string(), 256)
    }
}

/// Opens a loopback TCP connection and completes the RFC 6455 upgrade handshake.
fn connect(host: &str, port: u16, path: &str, token: &str) -> io::Result<WebSocket> {
    if !matches!(host, "127.0.0.1" | "::1" | "localhost") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "loopback host required",
        ));
    }
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute path required",
        ));
    }
    let key = base64_encode(&random_bytes());
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Authorization: Bearer {token}\r\n\r\n"
    );
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_nodelay(true).ok();
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let (head, rest) = read_headers(&mut stream)?;

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line.split(' ').nth(1).unwrap_or("");
    if status != "101" {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("expected HTTP 101, got: {status_line}"),
        ));
    }
    let mut accept = None;
    let mut upgrade = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "sec-websocket-accept" => accept = Some(value.trim().to_string()),
                "upgrade" => upgrade = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    if !upgrade.is_some_and(|value| value.eq_ignore_ascii_case("websocket")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Upgrade: websocket",
        ));
    }
    if accept.as_deref() != Some(websocket_accept(&key).as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Sec-WebSocket-Accept",
        ));
    }

    let mut websocket = WebSocket {
        stream,
        decoder: FrameDecoder::new(false),
        pending: VecDeque::new(),
        close_sent: false,
    };
    if !rest.is_empty() {
        let events = websocket
            .decoder
            .push(&rest)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.reason))?;
        websocket.pending.extend(events);
    }
    Ok(websocket)
}

/// Reads the next JSON control object, transparently answering protocol pings.
fn read_control(websocket: &mut WebSocket) -> Result<serde_json::Value, Box<dyn Error>> {
    loop {
        match websocket.read_message()? {
            Message::Text(text) => return Ok(serde_json::from_str(&text)?),
            Message::Ping(payload) => websocket.pong(&payload)?,
            Message::Pong(_) => {}
            Message::Close { code, reason } => {
                return Err(format!("relay closed the connection: {code} {reason}").into());
            }
        }
    }
}

fn control_type(value: &serde_json::Value) -> &str {
    value["type"].as_str().unwrap_or("")
}

fn run() -> Result<(), Box<dyn Error>> {
    let token = std::env::var("XEIP_DEV_TOKEN")?;
    if token.len() < 16 {
        return Err("XEIP_DEV_TOKEN must be at least 16 bytes".into());
    }
    let port: u16 = std::env::var("XEIP_PORT")
        .unwrap_or_else(|_| "8787".into())
        .parse()?;
    if port == 0 {
        return Err("XEIP_PORT must be nonzero".into());
    }
    let fixture: Envelope = serde_json::from_str(include_str!(
        "../../../conformance/fixtures/message.valid.json"
    ))?;
    fixture.validate()?;
    let entity = fixture
        .recipient
        .as_deref()
        .ok_or("fixture needs a recipient")?;

    let mut websocket = connect("127.0.0.1", port, "/ws", &token)?;
    websocket.subscribe(&fixture.session, entity, None)?;
    let subscribed = read_control(&mut websocket)?;
    if control_type(&subscribed) != "subscribed" {
        return Err(format!("expected subscribed, got {subscribed}").into());
    }
    println!("{{\"type\":\"ready\"}}");

    websocket.send_envelope(&fixture)?;
    loop {
        let control = read_control(&mut websocket)?;
        match control_type(&control) {
            "accepted" => {
                println!("{{\"type\":\"accepted\"}}");
                break;
            }
            "message" => println!("{{\"type\":\"message\"}}"),
            "gap" => println!("{{\"type\":\"gap\"}}"),
            "error" => return Err(format!("relay error: {control}").into()),
            other => return Err(format!("unexpected control: {other}").into()),
        }
    }
    websocket.close(CLOSE_NORMAL, "")?;
    println!("{{\"type\":\"done\"}}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Rust websocket peer: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a single unmasked server-side frame for decoder tests.
    fn server_frame(opcode: u8, payload: &[u8], fin: bool) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.push(if fin { 0x80 } else { 0x00 } | opcode);
        if payload.len() <= 125 {
            frame.push(payload.len() as u8);
        } else if payload.len() <= usize::from(u16::MAX) {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn masking_round_trip_through_client_encoder() {
        let mask = [0x11, 0x22, 0x33, 0x44];
        let payload = b"masked payload \xf0\x9f\x90\x88";
        let frame = encode_frame(OP_TEXT, payload, true, mask);
        assert_eq!(frame[1] & 0x80, 0x80, "mask bit set");
        let mut decoder = FrameDecoder::new(true);
        let events = decoder.push(&frame).unwrap();
        assert_eq!(events, vec![Message::Text("masked payload 🐈".into())]);
        assert_eq!(decoder.buffer.len(), 0);

        let mut bytes = payload.to_vec();
        apply_mask(&mut bytes, &mask);
        assert_ne!(&bytes, payload);
        apply_mask(&mut bytes, &mask);
        assert_eq!(&bytes, payload);
    }

    #[test]
    fn reassembles_fragmented_text_with_interleaved_control() {
        let mut decoder = FrameDecoder::new(false);
        let mut events = decoder.push(&server_frame(OP_TEXT, b"hel", false)).unwrap();
        assert!(events.is_empty());
        events.extend(decoder.push(&server_frame(OP_PING, b"hb", true)).unwrap());
        events.extend(
            decoder
                .push(&server_frame(OP_CONTINUATION, b"lo \xf0\x9f", false))
                .unwrap(),
        );
        events.extend(
            decoder
                .push(&server_frame(OP_CONTINUATION, b"\x90\x88", true))
                .unwrap(),
        );
        assert_eq!(
            events,
            vec![
                Message::Ping(b"hb".to_vec()),
                Message::Text("hello 🐈".into())
            ]
        );
    }

    #[test]
    fn fragmented_client_send_round_trips() {
        let text = std::str::from_utf8(b"fragmented \xf0\x9f\x90\x88 payload").unwrap();
        let mut wire = Vec::new();
        let chunks: Vec<&[u8]> = text.as_bytes().chunks(4).collect();
        for (index, part) in chunks.iter().enumerate() {
            let opcode = if index == 0 { OP_TEXT } else { OP_CONTINUATION };
            let fin = index + 1 == chunks.len();
            wire.extend_from_slice(&encode_frame(opcode, part, fin, [1, 2, 3, 4]));
        }
        assert_eq!(
            FrameDecoder::new(true).push(&wire).unwrap(),
            vec![Message::Text(text.into())]
        );
    }

    #[test]
    fn handles_control_frames_and_replies() {
        let mut decoder = FrameDecoder::new(false);
        let events = decoder.push(&server_frame(OP_PING, b"ping", true)).unwrap();
        assert_eq!(events, vec![Message::Ping(b"ping".to_vec())]);
        let events = decoder.push(&server_frame(OP_PONG, b"pong", true)).unwrap();
        assert_eq!(events, vec![Message::Pong(b"pong".to_vec())]);
        // A client pong is masked and round-trips.
        let frame = encode_frame(OP_PONG, b"pong", true, [9, 8, 7, 6]);
        assert_eq!(
            FrameDecoder::new(true).push(&frame).unwrap(),
            vec![Message::Pong(b"pong".to_vec())]
        );
    }

    #[test]
    fn parses_close_frames() {
        let mut decoder = FrameDecoder::new(false);
        let mut payload = CLOSE_NORMAL.to_be_bytes().to_vec();
        payload.extend_from_slice(b"bye");
        let events = decoder
            .push(&server_frame(OP_CLOSE, &payload, true))
            .unwrap();
        assert_eq!(
            events,
            vec![Message::Close {
                code: CLOSE_NORMAL,
                reason: "bye".into()
            }]
        );
        // An empty close payload implies a normal closure.
        assert_eq!(
            decoder.push(&server_frame(OP_CLOSE, b"", true)).unwrap(),
            vec![Message::Close {
                code: CLOSE_NORMAL,
                reason: String::new()
            }]
        );
        // A one-byte payload is a protocol error.
        assert_eq!(
            decoder
                .push(&server_frame(OP_CLOSE, b"\x03", true))
                .unwrap_err()
                .code,
            CLOSE_PROTOCOL
        );
    }

    #[test]
    fn rejects_oversized_frames_and_messages() {
        let mut oversized = vec![0x81u8, 127];
        oversized.extend_from_slice(&(MAX_FRAME as u64 + 1).to_be_bytes());
        assert_eq!(
            FrameDecoder::new(false).push(&oversized).unwrap_err().code,
            CLOSE_TOO_BIG
        );

        let mut decoder = FrameDecoder::new(false);
        decoder
            .push(&server_frame(OP_TEXT, &vec![b'a'; MAX_FRAME], false))
            .unwrap();
        assert_eq!(
            decoder
                .push(&server_frame(OP_CONTINUATION, b"x", true))
                .unwrap_err()
                .code,
            CLOSE_TOO_BIG
        );
    }

    #[test]
    fn rejects_invalid_server_frames() {
        // Masked server frame.
        let masked = encode_frame(OP_TEXT, b"nope", true, [1, 2, 3, 4]);
        assert_eq!(
            FrameDecoder::new(false).push(&masked).unwrap_err().code,
            CLOSE_PROTOCOL
        );
        // Reserved bit set.
        let mut reserved = server_frame(OP_TEXT, b"x", true);
        reserved[0] |= 0x40;
        assert_eq!(
            FrameDecoder::new(false).push(&reserved).unwrap_err().code,
            CLOSE_PROTOCOL
        );
        // Binary is unsupported.
        assert_eq!(
            FrameDecoder::new(false)
                .push(&server_frame(OP_BINARY, b"x", true))
                .unwrap_err()
                .code,
            CLOSE_UNSUPPORTED
        );
        // Continuation without a started message.
        assert_eq!(
            FrameDecoder::new(false)
                .push(&server_frame(OP_CONTINUATION, b"x", true))
                .unwrap_err()
                .code,
            CLOSE_PROTOCOL
        );
        // Invalid UTF-8 text.
        assert_eq!(
            FrameDecoder::new(false)
                .push(&server_frame(OP_TEXT, &[0xff, 0xfe, 0xfd], true))
                .unwrap_err()
                .code,
            CLOSE_INVALID_PAYLOAD
        );
        // Non-final control frame.
        assert_eq!(
            FrameDecoder::new(false)
                .push(&server_frame(OP_PING, b"x", false))
                .unwrap_err()
                .code,
            CLOSE_PROTOCOL
        );
    }

    #[test]
    fn incremental_decoding_across_byte_boundaries() {
        let wire = server_frame(OP_TEXT, "split".as_bytes(), true);
        let mut decoder = FrameDecoder::new(false);
        let mut events = Vec::new();
        for byte in &wire {
            events.extend(decoder.push(&[*byte]).unwrap());
        }
        assert_eq!(events, vec![Message::Text("split".into())]);
    }

    #[test]
    fn sha1_matches_known_vectors() {
        let digest = sha1(b"abc");
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
        let empty = sha1(b"");
        let hex: String = empty.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (input, expected) in [
            (&b""[..], ""),
            (&b"f"[..], "Zg=="),
            (&b"fo"[..], "Zm8="),
            (&b"foo"[..], "Zm9v"),
            (&b"foob"[..], "Zm9vYg=="),
            (&b"fooba"[..], "Zm9vYmE="),
            (&b"foobar"[..], "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input), expected);
        }
    }

    #[test]
    fn websocket_accept_matches_rfc6455_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn random_bytes_are_not_all_zero() {
        let mut distinct = false;
        for _ in 0..4 {
            if random_bytes().iter().any(|byte| *byte != 0) {
                distinct = true;
            }
        }
        assert!(distinct);
    }

    #[test]
    #[ignore = "starts nothing; point it at a running relay to exercise a live socket"]
    fn live_relay_smoke() {
        // Usage:
        //   1. XEIP_DEV_TOKEN=... node services/relay/server.mjs
        //   2. XEIP_DEV_TOKEN=... XEIP_PORT=8787 \
        //        cargo test -p xeip-core --example websocket_peer -- --ignored --nocapture
        let Ok(token) = std::env::var("XEIP_DEV_TOKEN") else {
            eprintln!("XEIP_DEV_TOKEN not set; nothing to do");
            return;
        };
        let port: u16 = std::env::var("XEIP_PORT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(8787);
        let mut websocket = connect("127.0.0.1", port, "/ws", &token).expect("handshake");
        websocket
            .subscribe("urn:xeip:session:demo", "urn:xeip:entity:agent-01", None)
            .expect("subscribe");
        assert_eq!(
            control_type(&read_control(&mut websocket).expect("subscribed")),
            "subscribed"
        );
        websocket.close(CLOSE_NORMAL, "").expect("close");
    }
}
