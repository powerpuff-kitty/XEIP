/// Whether `text` is an RFC 3339 instant in UTC (`YYYY-MM-DDTHH:MM:SS[.fff]Z`).
/// Offsets are rejected: the profile fixes UTC.
pub(crate) fn is_utc_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    let digit = |index: usize| bytes[index].is_ascii_digit();
    let fixed = digit(0)
        && digit(1)
        && digit(2)
        && digit(3)
        && bytes[4] == b'-'
        && digit(5)
        && digit(6)
        && bytes[7] == b'-'
        && digit(8)
        && digit(9)
        && bytes[10] == b'T'
        && digit(11)
        && digit(12)
        && bytes[13] == b':'
        && digit(14)
        && digit(15)
        && bytes[16] == b':'
        && digit(17)
        && digit(18);
    if !fixed {
        return false;
    }
    if bytes[19] == b'Z' {
        return bytes.len() == 20;
    }
    if bytes[19] != b'.' {
        return false;
    }
    let mut index = 20;
    let start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    index > start && index + 1 == bytes.len() && bytes[index] == b'Z'
}

/// Days from the civil date `y-m-d` to 1970-01-01 (Howard Hinnant's algorithm).
/// This is calendar arithmetic, not a cryptographic primitive.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Whole epoch seconds of a UTC instant already validated by
/// [`is_utc_timestamp`]. Fractional seconds are truncated, matching
/// `parseUtcSeconds` in `tools/identity-status.mjs`.
pub(crate) fn parse_utc_seconds(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    let number = |start: usize, end: usize| text.get(start..end)?.parse::<i64>().ok();
    let year = number(0, 4)?;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
}
