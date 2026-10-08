use crate::{ValidationError, PROTOCOL_VERSION};
use serde::{Deserialize, Deserializer};

fn component(value: &str, extra: &[u8]) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1..index + 3]
                    .iter()
                    .all(u8::is_ascii_hexdigit)
            {
                return false;
            }
            index += 3;
        } else if byte.is_ascii_alphanumeric()
            || b"-._~!$&'()*+,;=".contains(&byte)
            || extra.contains(&byte)
        {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

fn authority(value: &str) -> bool {
    let (user, host_port) = value.rsplit_once('@').unwrap_or(("", value));
    if !component(user, b":") {
        return false;
    }
    if let Some(literal) = host_port.strip_prefix('[') {
        let Some((address, tail)) = literal.split_once(']') else {
            return false;
        };
        let port_valid = tail.is_empty()
            || tail
                .strip_prefix(':')
                .is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit()));
        let address_valid = if let Some(future) = address
            .strip_prefix('v')
            .or_else(|| address.strip_prefix('V'))
        {
            future.split_once('.').is_some_and(|(version, host)| {
                !version.is_empty()
                    && version.bytes().all(|b| b.is_ascii_hexdigit())
                    && !host.is_empty()
                    && !host.contains('%')
                    && component(host, b":")
            })
        } else {
            address.parse::<std::net::Ipv6Addr>().is_ok()
        };
        port_valid && address_valid
    } else {
        let (host, port) = host_port.split_once(':').unwrap_or((host_port, ""));
        component(host, b"") && port.bytes().all(|b| b.is_ascii_digit())
    }
}

// RFC 3986 syntax: ports are digit strings, not transport-specific u16 values.
fn valid_uri(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    if !scheme
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic())
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
    {
        return false;
    }
    let (before_fragment, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (hierarchy, query) = before_fragment
        .split_once('?')
        .unwrap_or((before_fragment, ""));
    if !component(query, b":@/?") || !component(fragment, b":@/?") {
        return false;
    }
    let path = if let Some(after_slashes) = hierarchy.strip_prefix("//") {
        let at = after_slashes.find('/').unwrap_or(after_slashes.len());
        if !authority(&after_slashes[..at]) {
            return false;
        }
        &after_slashes[at..]
    } else {
        hierarchy
    };
    component(path, b":@/")
}

// Optional fields may be absent; an explicit JSON null is not a schema-valid string.
pub(crate) fn optional_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}

pub(crate) fn ensure_string(
    field: &'static str,
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), ValidationError> {
    let length = value.chars().count();
    if (min..=max).contains(&length) {
        Ok(())
    } else {
        Err(ValidationError {
            field,
            reason: "invalid string length",
        })
    }
}

pub(crate) fn ensure_uri(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if valid_uri(value) {
        Ok(())
    } else {
        Err(ValidationError {
            field,
            reason: "expected absolute URI",
        })
    }
}

pub(crate) fn ensure_version(value: &str) -> Result<(), ValidationError> {
    if value == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ValidationError {
            field: "xeip",
            reason: "unsupported XEIP version",
        })
    }
}

pub(crate) fn ensure_utc(field: &'static str, value: &str) -> Result<(), ValidationError> {
    let error = || ValidationError {
        field,
        reason: "expected UTC RFC3339 date-time",
    };
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes.last() != Some(&b'Z')
    {
        return Err(error());
    }
    let fraction = &bytes[19..bytes.len() - 1];
    if !fraction.is_empty()
        && (fraction[0] != b'.'
            || fraction.len() < 2
            || !fraction[1..].iter().all(u8::is_ascii_digit))
    {
        return Err(error());
    }
    let mut parts = [0u32; 6];
    for (i, (start, end)) in [(0, 4), (5, 7), (8, 10), (11, 13), (14, 16), (17, 19)]
        .iter()
        .enumerate()
    {
        let digits = &bytes[*start..*end];
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(error());
        }
        parts[i] = digits
            .iter()
            .fold(0, |n, digit| n * 10 + u32::from(digit - b'0'));
    }
    let [year, month, day, hour, minute, second] = parts;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        0,
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day == 0
        || day > days[month as usize]
        || hour > 23
        || minute > 59
        || !(second < 60 || (second == 60 && hour == 23 && minute == 59))
    {
        return Err(error());
    }
    Ok(())
}
