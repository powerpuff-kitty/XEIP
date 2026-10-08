//! Development-only HTTP/SSE peer. Transport code stays outside xeip-core.
use serde::Deserialize;
use std::error::Error;
use std::io::{self, Read, Write};
use std::time::Duration;
use xeip_core::Envelope;

const MAX_FRAME: usize = 128 * 1024;

#[derive(Debug, PartialEq)]
struct Frame {
    event: String,
    data: String,
}

#[derive(Default)]
struct SseDecoder {
    line: Vec<u8>,
    event: String,
    data: Vec<String>,
    frame_size: usize,
    skip_lf: bool,
    read_first_line: bool,
}

impl SseDecoder {
    fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<Frame>> {
        let mut frames = Vec::new();
        for &byte in bytes {
            if self.skip_lf {
                self.skip_lf = false;
                if byte == b'\n' {
                    continue;
                }
            }
            self.frame_size += 1;
            if self.frame_size > MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SSE frame exceeds 128 KiB",
                ));
            }
            if byte == b'\r' || byte == b'\n' {
                self.skip_lf = byte == b'\r';
                let line = String::from_utf8(std::mem::take(&mut self.line))
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                let line = if self.read_first_line {
                    line.as_str()
                } else {
                    self.read_first_line = true;
                    line.strip_prefix('\u{feff}').unwrap_or(&line)
                };
                if line.is_empty() {
                    if !self.data.is_empty() {
                        frames.push(Frame {
                            event: if self.event.is_empty() {
                                "message".into()
                            } else {
                                std::mem::take(&mut self.event)
                            },
                            data: self.data.join("\n"),
                        });
                    }
                    self.event.clear();
                    self.data.clear();
                    self.frame_size = 0;
                } else {
                    let (field, value) = line.split_once(':').unwrap_or((line, ""));
                    let value = value.strip_prefix(' ').unwrap_or(value);
                    match field {
                        "event" => self.event = value.into(),
                        "data" => self.data.push(value.into()),
                        _ => {} // Includes comments, id and retry; no reconnect/replay.
                    }
                }
            } else {
                self.line.push(byte);
            }
        }
        Ok(frames)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acceptance {
    accepted: bool,
    delivered: u64,
    #[serde(default)]
    duplicate: bool,
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
    // Never accept a remote URL or forward the credential through proxies/redirects.
    let base = format!("http://127.0.0.1:{port}");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();
    let fixture: Envelope = serde_json::from_str(include_str!(
        "../../../conformance/fixtures/message.valid.json"
    ))?;
    fixture.validate()?;
    let entity = fixture
        .recipient
        .as_deref()
        .ok_or("fixture needs a recipient")?;
    let authorization = format!("Bearer {token}");
    let mut stream = agent
        .get(format!("{base}/events"))
        .query("session", &fixture.session)
        .query("entity", entity)
        .header("Authorization", &authorization)
        .call()?;
    let content_type = stream
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if stream.status() != 200 || !content_type.eq_ignore_ascii_case("text/event-stream") {
        return Err("expected HTTP 200 text/event-stream".into());
    }
    println!("{{\"type\":\"ready\"}}");
    io::stdout().flush()?;
    let mut reader = stream.body_mut().as_reader();
    let mut decoder = SseDecoder::default();
    let mut buffer = [0u8; 2048];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Err("SSE stream ended".into());
        }
        for frame in decoder.push(&buffer[..count])? {
            if frame.event != "xeip.message" {
                continue;
            }
            let mut message: Envelope = serde_json::from_str(&frame.data)?;
            message.validate()?;
            if message.session != fixture.session
                || message.recipient.as_deref() != Some(entity)
                || message.sender != fixture.sender
            {
                return Err("envelope does not match the demonstration participants".into());
            }
            // Echo the fixture's wire content with new routing and correlation fields.
            // Selectors alone are not identity proof; this echo never executes a command.
            message.reply_to = Some(message.id.clone());
            message.id.push_str("-reply");
            message.recipient = Some(std::mem::replace(&mut message.sender, entity.into()));
            message.validate()?;
            let mut response = agent
                .post(format!("{base}/messages"))
                .header("Authorization", &authorization)
                .header("Content-Type", "application/json")
                .send(serde_json::to_string(&message)?)?;
            if response.status() != 202 {
                return Err("expected HTTP 202 acceptance".into());
            }
            let mut body = Vec::new();
            response
                .body_mut()
                .as_reader()
                .take(4097)
                .read_to_end(&mut body)?;
            if body.len() > 4096 {
                return Err("oversized acceptance response".into());
            }
            let acceptance: Acceptance = serde_json::from_slice(&body)?;
            if !acceptance.accepted
                || acceptance.duplicate
                || acceptance.delivered == 0
                || acceptance.delivered > 9_007_199_254_740_991
            {
                return Err("reply was not written to a subscriber".into());
            }
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Rust local relay peer: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acceptance_supports_optional_boolean_duplicate_flag() {
        for wire in [
            r#"{"accepted":true,"delivered":1}"#,
            r#"{"accepted":true,"delivered":1,"duplicate":false}"#,
            r#"{"accepted":true,"delivered":0,"duplicate":true}"#,
        ] {
            assert!(serde_json::from_str::<Acceptance>(wire).is_ok());
        }
        for wire in [
            r#"{"accepted":true,"delivered":0,"duplicate":null}"#,
            r#"{"accepted":true,"delivered":0,"duplicate":"true"}"#,
            r#"{"accepted":true,"delivered":0,"duplicate":1}"#,
        ] {
            assert!(serde_json::from_str::<Acceptance>(wire).is_err());
        }
    }

    #[test]
    fn fragmented_utf8_and_all_line_endings() {
        for ending in ["\n", "\r\n", "\r"] {
            let wire =
                format!("event: xeip.message{ending}data: {{\"cat\":\"🐈\"}}{ending}{ending}");
            let mut decoder = SseDecoder::default();
            let mut frames = Vec::new();
            for byte in wire.as_bytes() {
                frames.extend(decoder.push(&[*byte]).unwrap());
            }
            assert_eq!(
                frames,
                vec![Frame {
                    event: "xeip.message".into(),
                    data: "{\"cat\":\"🐈\"}".into()
                }]
            );
        }
    }

    #[test]
    fn bom_comments_multiline_data_and_empty_event() {
        let mut decoder = SseDecoder::default();
        assert_eq!(
            decoder
                .push(
                    "\u{feff}: heartbeat\n\nevent: other\ndata: first\ndata:  second\n\ndata:\n\n"
                        .as_bytes()
                )
                .unwrap(),
            vec![
                Frame {
                    event: "other".into(),
                    data: "first\n second".into()
                },
                Frame {
                    event: "message".into(),
                    data: "".into()
                },
            ]
        );
    }

    #[test]
    fn oversized_unterminated_line_is_rejected() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(&vec![b'x'; MAX_FRAME + 1]).is_err());
    }

    #[test]
    fn comments_count_toward_unfinished_frame_limit() {
        let mut decoder = SseDecoder::default();
        let comment = format!(":{}\n", "x".repeat(1024));
        let mut rejected = false;
        for _ in 0..130 {
            if decoder.push(comment.as_bytes()).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
    }

    #[test]
    fn limit_is_per_frame_and_incomplete_event_is_not_dispatched() {
        let mut decoder = SseDecoder::default();
        let wire = "data: hello\n\n".repeat(12000) + "data: incomplete\n";
        let frames = decoder.push(wire.as_bytes()).unwrap();
        assert_eq!(frames.len(), 12000);
        assert!(frames.iter().all(|frame| frame.data == "hello"));
        assert!(decoder.push(b"").unwrap().is_empty());
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        assert!(SseDecoder::default().push(b"data: \xff\n\n").is_err());
    }
}
