use serde_json::{Map, Value};
use std::fmt;

/// Largest integer that round-trips through an IEEE-754 double exactly. The
/// strict pre-parse gate rejects any integer outside `±(2^53 - 1)`.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// RFC 8785 (JSON Canonicalization Scheme) of a parsed JSON value: object keys
/// sorted by UTF-16 code units, no insignificant whitespace, ECMAScript number
/// formatting and JSON string escaping, arrays in order.
///
/// This is deterministic serialization, not a cryptographic primitive (ADR
/// 0007 permits it alongside an audited signing library). Numbers are treated
/// as IEEE-754 doubles, so `-0` maps to `0` and values format exactly as
/// ECMAScript `Number::toString` does within the interoperable range.
pub fn canonicalize_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            let float = number
                .as_f64()
                .expect("a JSON number is always representable as f64");
            out.push_str(&format_ecmascript_number(float));
        }
        Value::String(text) => write_json_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(key, out);
                out.push(':');
                write_canonical_json(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// Serialize a string as a JSON quoted string with the ecosystem's escaping:
/// short escapes for the JSON control characters, literal non-ASCII UTF-8 and
/// `/` left unescaped.
fn write_json_string(text: &str, out: &mut String) {
    let escaped = serde_json::to_string(text).expect("a string always serializes to JSON");
    out.push_str(&escaped);
}

/// Format an `f64` exactly as ECMAScript `Number::toString` (and therefore
/// `JSON.stringify`) does, per RFC 8785 §3.2.2.3. Finite values only.
fn format_ecmascript_number(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    if value < 0.0 {
        let mut out = String::from("-");
        out.push_str(&format_ecmascript_number(-value));
        return out;
    }

    // Get the shortest correctly-rounded significant digits, then apply the
    // ECMAScript fixed/exponential decision. Rust's own `{:e}`/`{}` formatting
    // tie-breaks an exact decimal midpoint away from zero (for example
    // `2084516549501568.25`), which disagrees with the ECMAScript/RFC 8785 rule
    // of choosing the even final digit; `serde_json`'s float formatter follows
    // the required shortest-round-trip rule, so the digits are taken from it.
    let (digits, point) = shortest_significant_digits(value);
    let digit_count = digits.len() as i32;

    if digit_count <= point && point <= 21 {
        let mut out = digits;
        out.push_str(&"0".repeat((point - digit_count) as usize));
        out
    } else if 0 < point && point <= 21 {
        let point = point as usize;
        format!("{}.{}", &digits[..point], &digits[point..])
    } else if -6 < point && point <= 0 {
        format!("0.{}{}", "0".repeat((-point) as usize), digits)
    } else {
        let exponent = point - 1;
        let sign = if exponent < 0 { '-' } else { '+' };
        let first = &digits[..1];
        let rest = &digits[1..];
        if rest.is_empty() {
            format!("{first}e{sign}{}", exponent.abs())
        } else {
            format!("{first}.{rest}e{sign}{}", exponent.abs())
        }
    }
}

/// The shortest significant decimal digits of a positive, finite `f64` and the
/// position of the decimal point relative to those digits, such that the value
/// is `digits * 10^(point - digits.len())`.
///
/// RFC 8785 §3.2.2.3 (and ECMAScript `Number::toString`) require the shortest
/// digit string that round-trips, breaking an exact midpoint toward the even
/// final digit. `serde_json`'s float formatter implements that rule; parsing
/// its output normalises away its own fixed/exponential style so the digits can
/// be re-rendered with the ECMAScript thresholds in
/// [`format_ecmascript_number`].
fn shortest_significant_digits(value: f64) -> (String, i32) {
    let text = serde_json::Number::from_f64(value)
        .expect("a finite number is representable")
        .to_string();
    let (mantissa, exponent) = match text.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (
            mantissa,
            exponent
                .parse::<i32>()
                .expect("a serde_json exponent is an integer"),
        ),
        None => (text.as_str(), 0),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((integer, fraction)) => (integer, fraction),
        None => (mantissa, ""),
    };

    let mut digits: Vec<u8> = integer.bytes().chain(fraction.bytes()).collect();
    let mut point = integer.len() as i32 + exponent;
    let leading = digits.iter().take_while(|&&byte| byte == b'0').count();
    digits.drain(..leading);
    point -= leading as i32;
    while digits.last() == Some(&b'0') {
        digits.pop();
    }

    (
        String::from_utf8(digits).expect("decimal digits are ASCII"),
        point,
    )
}

/// Reason a JSON document was rejected by [`strict_parse`].
///
/// The message is intended for diagnostics only; the signed-envelope entry
/// points collapse every strict-parse failure to
/// [`crate::SignedEnvelopeError::MalformedEnvelope`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictParseError {
    message: String,
}

impl StrictParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for StrictParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StrictParseError {}

/// Strict JSON parser, the Rust twin of `strictParse` in
/// `tools/signed-envelope.mjs`. Before canonicalization it rejects the
/// ambiguity that would let two different wire byte sequences share one
/// signature:
///
/// - duplicate object member names,
/// - lone surrogate escapes (`\uD800`, `\uDC00` and an unpaired high surrogate
///   followed by a non-low escape),
/// - numbers that are non-finite (`1e999`),
/// - integer values outside `±(2^53-1)`.
///
/// What `serde_json` already enforces: its parser rejects lone surrogate
/// escapes (`unexpected end of hex escape` / `lone leading surrogate in hex
/// escape`) and non-finite numbers (`number out of range`), and a raw lone
/// surrogate is impossible in a Rust `&str` (UTF-8 invariant). What `serde_json`
/// cannot express: deserializing into [`Value`] silently keeps the *last* value
/// for a duplicate key, so duplicate detection is implemented here by hand.
///
/// Integers are parsed as IEEE-754 doubles, matching the JavaScript reference
/// (which applies `Number.isInteger` to the parsed double), so `1e15` is
/// accepted while `9007199254740992` is rejected.
pub fn strict_parse(text: &str) -> Result<Value, StrictParseError> {
    let mut parser = StrictJsonParser::new(text);
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if !parser.at_end() {
        return Err(parser.error("unexpected trailing content"));
    }
    Ok(value)
}

struct StrictJsonParser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> StrictJsonParser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn error(&self, message: &str) -> StrictParseError {
        StrictParseError::new(format!("{message} at position {}", self.pos))
    }

    fn at_end(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while let Some(byte) = self.peek() {
            if matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), StrictParseError> {
        if self.peek() != Some(byte) {
            return Err(self.error(&format!("expected {}", byte as char)));
        }
        self.pos += 1;
        Ok(())
    }

    fn parse_value(&mut self) -> Result<Value, StrictParseError> {
        self.skip_whitespace();
        match self.peek() {
            None => Err(self.error("unexpected end of input")),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::String(self.parse_string()?)),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(b't') => self.parse_literal("true", Value::Bool(true)),
            Some(b'f') => self.parse_literal("false", Value::Bool(false)),
            Some(b'n') => self.parse_literal("null", Value::Null),
            Some(byte) => Err(self.error(&format!("unexpected character {}", char::from(byte)))),
        }
    }

    fn parse_literal(&mut self, literal: &str, value: Value) -> Result<Value, StrictParseError> {
        if self.text[self.pos..].starts_with(literal) {
            self.pos += literal.len();
            Ok(value)
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn parse_object(&mut self) -> Result<Value, StrictParseError> {
        self.expect(b'{')?;
        self.skip_whitespace();
        let mut object = Map::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(object));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a string object key"));
            }
            let key = self.parse_string()?;
            if object.contains_key(&key) {
                return Err(self.error("duplicate object member name"));
            }
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.parse_value()?;
            object.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(object));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn parse_array(&mut self) -> Result<Value, StrictParseError> {
        self.expect(b'[')?;
        self.skip_whitespace();
        let mut array = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(array));
        }
        loop {
            array.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(array));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, StrictParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = match self.peek() {
                Some(byte) => byte,
                None => return Err(self.error("unterminated string")),
            };
            if byte == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if byte == b'\\' {
                self.pos += 1;
                let escape = self
                    .peek()
                    .ok_or_else(|| self.error("unterminated escape"))?;
                self.pos += 1;
                match escape {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000c}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => self.parse_unicode_escape(&mut out)?,
                    _ => return Err(self.error("invalid escape")),
                }
                continue;
            }
            if byte < 0x20 {
                return Err(self.error("unescaped control character in string"));
            }
            // `self.pos` is always on a UTF-8 boundary here, so this is valid.
            let ch = self.text[self.pos..]
                .chars()
                .next()
                .expect("non-empty remaining string");
            out.push(ch);
            self.pos += ch.len_utf8();
        }
    }

    fn parse_unicode_escape(&mut self, out: &mut String) -> Result<(), StrictParseError> {
        let first = self.read_hex4()?;
        if (0xd800..=0xdbff).contains(&first) {
            // A high surrogate must be immediately followed by a low escape.
            if self.bytes.get(self.pos) != Some(&b'\\')
                || self.bytes.get(self.pos + 1) != Some(&b'u')
            {
                return Err(self.error("string contains a lone high surrogate"));
            }
            self.pos += 2;
            let second = self.read_hex4()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(self.error("string contains a lone high surrogate"));
            }
            let scalar = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
            out.push(char::from_u32(scalar).expect("a valid surrogate pair is a scalar value"));
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(self.error("string contains a lone low surrogate"));
        } else {
            out.push(char::from_u32(first).expect("a non-surrogate code unit is a scalar value"));
        }
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u32, StrictParseError> {
        let end = self.pos + 4;
        if end > self.bytes.len() {
            return Err(self.error("invalid \\u escape"));
        }
        let digits = &self.bytes[self.pos..end];
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(self.error("invalid \\u escape"));
        }
        let value = u32::from_str_radix(&self.text[self.pos..end], 16)
            .map_err(|_| self.error("invalid \\u escape"))?;
        self.pos = end;
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, StrictParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(byte) if byte.is_ascii_digit() => {
                while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.error("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                return Err(self.error("invalid number"));
            }
            while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                return Err(self.error("invalid number"));
            }
            while matches!(self.peek(), Some(byte) if byte.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let token = &self.text[start..self.pos];
        let value: f64 = token.parse().map_err(|_| self.error("invalid number"))?;
        if !value.is_finite() {
            return Err(self.error("non-finite number"));
        }
        if value.fract() == 0.0 && value.abs() > MAX_SAFE_INTEGER as f64 {
            return Err(self.error("integer outside the safe range"));
        }
        // Preserve the integer spelling when the token is a pure integer, so
        // the parsed value mirrors `serde_json`'s own representation.
        let number = if !token.contains(['.', 'e', 'E']) {
            match token.parse::<i64>() {
                Ok(value) => serde_json::Number::from(value),
                Err(_) => match token.parse::<u64>() {
                    Ok(value) => serde_json::Number::from(value),
                    Err(_) => serde_json::Number::from_f64(value)
                        .ok_or_else(|| self.error("non-finite number"))?,
                },
            }
        } else {
            serde_json::Number::from_f64(value).ok_or_else(|| self.error("non-finite number"))?
        };
        Ok(Value::Number(number))
    }
}
