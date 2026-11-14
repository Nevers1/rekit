//! A WebSocket client, just big enough for the Chrome DevTools Protocol.
//!
//! CDP is the only way to get at a live page: the DOM after scripts ran, the
//! network requests the page actually made, the cookies the server set, a
//! screenshot. The browser speaks it over a WebSocket, and a WebSocket is a
//! handful of bytes on top of TCP — so it is implemented here rather than
//! pulling a TLS stack and an async runtime into a tool whose point is one
//! static binary. There is no TLS because CDP only listens on 127.0.0.1.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use anyhow::{bail, Context, Result};

/// A frame larger than this is a bug or a hostile server, not a screenshot.
const MAX_MESSAGE: usize = 256 << 20;

pub struct Ws {
    stream: TcpStream,
    /// Bytes read from the socket but not yet consumed as a message.
    pending: Vec<u8>,
}

impl Ws {
    /// Open a `ws://host:port/path` connection.
    pub fn connect(url: &str, timeout: Duration) -> Result<Self> {
        let rest = match url.strip_prefix("wss://") {
            Some(_) => bail!("wss:// is not supported: the DevTools endpoint is local and plain"),
            None => url
                .strip_prefix("ws://")
                .with_context(|| format!("not a ws:// url: {url}"))?,
        };
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse::<u16>().context("bad port")?),
            None => (authority, 80),
        };
        let mut addrs = (host, port)
            .to_socket_addrs()
            .with_context(|| format!("cannot resolve {host}:{port}"))?;
        let addr = addrs
            .next()
            .with_context(|| format!("no address for {host}"))?;
        let token = base64(&random_bytes::<16>());
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {authority}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {token}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n"
        );

        let mut stream = TcpStream::connect_timeout(&addr, timeout)
            .with_context(|| format!("cannot connect to {addr}"))?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        stream.write_all(request.as_bytes())?;

        let mut ws = Ws {
            stream,
            pending: Vec::new(),
        };
        let head = ws.read_http_head()?;
        let status = head.lines().next().unwrap_or_default();
        if !status.contains(" 101 ") {
            bail!("websocket handshake refused: {status}");
        }
        Ok(ws)
    }

    /// Read until the blank line that ends the HTTP response headers.
    fn read_http_head(&mut self) -> Result<String> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = self.stream.read(&mut byte)?;
            if n == 0 {
                bail!("websocket handshake: the server closed the connection");
            }
            head.push(byte[0]);
            if head.len() >= 4 && head[head.len() - 4..] == *b"\r\n\r\n" {
                break;
            }
            if head.len() > 16 * 1024 {
                bail!("websocket handshake: header too large");
            }
        }
        Ok(String::from_utf8_lossy(&head).to_string())
    }

    pub fn set_timeout(&self, timeout: Duration) -> Result<()> {
        self.stream.set_read_timeout(Some(timeout))?;
        Ok(())
    }

    /// Is there a byte waiting, within `timeout`?
    ///
    /// `peek` is used rather than `read` on purpose: a read that times out in
    /// the middle of a frame loses the bytes it already consumed, and a
    /// half-parsed frame is unrecoverable. Peeking never consumes anything, so
    /// polling for events cannot corrupt the stream.
    pub fn has_data(&self, timeout: Duration) -> Result<bool> {
        if !self.pending.is_empty() {
            return Ok(true);
        }
        self.stream.set_read_timeout(Some(timeout))?;
        let mut byte = [0u8; 1];
        match self.stream.peek(&mut byte) {
            Ok(0) => Ok(false),
            Ok(_) => Ok(true),
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Send one text frame. Client frames are always masked.
    pub fn send(&mut self, text: &str) -> Result<()> {
        let payload = text.as_bytes();
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x81); // FIN + text
        let mask_bit = 0x80u8;
        match payload.len() {
            n if n < 126 => frame.push(mask_bit | n as u8),
            n if n <= u16::MAX as usize => {
                frame.push(mask_bit | 126);
                frame.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                frame.push(mask_bit | 127);
                frame.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        let mask = random_mask();
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// The next text message, or `None` when the peer closed.
    ///
    /// Controls are answered here: a ping is a pong, a close ends the stream.
    pub fn recv(&mut self) -> Result<Option<String>> {
        let mut assembled: Vec<u8> = Vec::new();
        loop {
            let (opcode, fin, payload) = self.read_frame()?;
            match opcode {
                0x0 => {
                    // Continuation of the previous message.
                    assembled.extend_from_slice(&payload);
                    if assembled.len() > MAX_MESSAGE {
                        bail!("websocket message is too large");
                    }
                    if fin {
                        return Ok(Some(String::from_utf8_lossy(&assembled).to_string()));
                    }
                }
                0x1 | 0x2 => {
                    if fin {
                        if let Ok(text) = String::from_utf8(payload) {
                            return Ok(Some(text));
                        }
                        bail!("websocket binary frame where text was expected");
                    }
                    assembled = payload;
                }
                0x8 => return Ok(None),
                0x9 => self.write_control(0xA, &payload)?,
                0xA => {}
                other => bail!("unexpected websocket opcode {other:#x}"),
            }
        }
    }

    fn write_control(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let mut frame = Vec::with_capacity(payload.len() + 8);
        frame.push(0x80 | opcode);
        frame.push(0x80 | payload.len() as u8);
        let mask = random_mask();
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    fn read_frame(&mut self) -> Result<(u8, bool, Vec<u8>)> {
        let head = self.take(2)?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        let mut length = (head[1] & 0x7f) as u64;
        if length == 126 {
            let bytes = self.take(2)?;
            length = u16::from_be_bytes([bytes[0], bytes[1]]) as u64;
        } else if length == 127 {
            let bytes = self.take(8)?;
            length = u64::from_be_bytes(bytes.try_into().unwrap());
        }
        if length as usize > MAX_MESSAGE {
            bail!("websocket frame of {length} bytes is too large");
        }
        // A server must not mask, but a proxy or a test peer might.
        let mask = if masked { Some(self.take(4)?) } else { None };
        let mut payload = self.take(length as usize)?;
        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }
        Ok((opcode, fin, payload))
    }

    /// Read exactly `count` bytes, buffering whatever the OS hands over.
    fn take(&mut self, count: usize) -> Result<Vec<u8>> {
        while self.pending.len() < count {
            let mut chunk = [0u8; 8192];
            match self.stream.read(&mut chunk) {
                Ok(0) => bail!("websocket closed while reading a frame"),
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            }
        }
        let rest = self.pending.split_off(count);
        Ok(std::mem::replace(&mut self.pending, rest))
    }
}

/// Random bytes for the handshake key and the frame masks.
///
/// Nothing here authenticates anything: the key only stops a cached reply and
/// the mask only keeps frames well formed. `/dev/urandom` is used when it is
/// there, and the clock finishes the job when it is not (a sandbox without
/// `/dev` still gets a working connection).
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    let _ = std::fs::File::open("/dev/urandom").and_then(|mut file| {
        let mut pool = [0u8; 16];
        file.read_exact(&mut pool)?;
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = pool[index % 16];
        }
        Ok::<(), std::io::Error>(())
    });
    if out.iter().all(|byte| *byte == 0) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id() as u128;
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = ((nanos >> ((index % 8) * 8)) ^ pid) as u8;
        }
    }
    out
}

fn random_mask() -> [u8; 4] {
    random_bytes::<4>()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(triple >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[triple as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Base64 decode, for the screenshot CDP hands back.
pub fn base64_decode(text: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut bits = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\r' | b'\n' => continue,
            other => bail!("bad base64 byte {other:#x}"),
        } as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"hello"), "aGVsbG8=");
    }

    #[test]
    fn base64_round_trips() {
        for text in ["", "a", "ab", "abc", "hello, world", "\u{1f600}"] {
            let encoded = base64(text.as_bytes());
            assert_eq!(
                String::from_utf8(base64_decode(&encoded).unwrap()).unwrap(),
                text
            );
        }
    }

    /// A peer that answers the handshake and then speaks a scripted frame.
    fn fake_peer(frames: Vec<Vec<u8>>) -> (Ws, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                if socket.read(&mut byte).unwrap() == 0 {
                    return;
                }
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\
                      Sec-WebSocket-Accept: nonsense\r\n\r\n",
                )
                .unwrap();
            for frame in frames {
                socket.write_all(&frame).unwrap();
            }
            // Keep the socket open until the client is done.
            std::thread::sleep(Duration::from_millis(200));
        });
        let ws = Ws::connect(
            &format!("ws://127.0.0.1:{port}/devtools/page/x"),
            Duration::from_secs(2),
        )
        .unwrap();
        (ws, port)
    }

    fn unmasked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x80 | opcode];
        if payload.len() < 126 {
            frame.push(payload.len() as u8);
        } else {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn a_short_text_message_arrives() {
        let (mut ws, _) = fake_peer(vec![unmasked_frame(0x1, b"{\"id\":1}")]);
        assert_eq!(ws.recv().unwrap().as_deref(), Some("{\"id\":1}"));
    }

    #[test]
    fn a_long_message_is_read_across_the_126_boundary() {
        let text = "x".repeat(300);
        let (mut ws, _) = fake_peer(vec![unmasked_frame(0x1, text.as_bytes())]);
        assert_eq!(ws.recv().unwrap().as_deref(), Some(text.as_str()));
    }

    #[test]
    fn a_ping_is_answered_and_the_text_after_it_still_arrives() {
        let (mut ws, _) = fake_peer(vec![
            unmasked_frame(0x9, b"hi"),
            unmasked_frame(0x1, b"after"),
        ]);
        assert_eq!(ws.recv().unwrap().as_deref(), Some("after"));
    }

    #[test]
    fn a_fragmented_message_is_assembled() {
        let mut first = unmasked_frame(0x1, b"{\"a\":");
        first[0] &= 0x7f; // FIN off
        let (mut ws, _) = fake_peer(vec![first, unmasked_frame(0x0, b"1}")]);
        assert_eq!(ws.recv().unwrap().as_deref(), Some("{\"a\":1}"));
    }

    #[test]
    fn a_close_ends_the_stream() {
        let (mut ws, _) = fake_peer(vec![unmasked_frame(0x8, b"")]);
        assert!(ws.recv().unwrap().is_none());
    }

    #[test]
    fn a_masked_frame_from_the_peer_is_unmasked() {
        let payload = b"masked";
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![0x81, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(byte ^ mask[index % 4]);
        }
        let (mut ws, _) = fake_peer(vec![frame]);
        assert_eq!(ws.recv().unwrap().as_deref(), Some("masked"));
    }
}
