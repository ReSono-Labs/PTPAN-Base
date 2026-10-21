//! UTC timestamp parsing shared by every Base module and by Base callers.
//! Accepted form: `YYYY-MM-DDTHH:MM:SSZ` with an optional 1–9 digit fraction.

/// Largest clock difference tolerated between platforms (D12). It is applied
/// once per check, never added again at each hop.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct UtcInstant {
    pub year: u32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub nanos: u32,
}

impl UtcInstant {
    /// Seconds since the Unix epoch (fraction discarded).
    pub fn unix_seconds(self) -> i64 {
        let mut year = i64::from(self.year);
        let month = i64::from(self.month);
        let day = i64::from(self.day);
        if month <= 2 {
            year -= 1;
        }
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let adjusted_month = month + if month > 2 { -3 } else { 9 };
        let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
        let year_of_era_day =
            year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146097 + year_of_era_day - 719468;
        days * 86400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

pub fn parse_utc(value: &str) -> Option<UtcInstant> {
    let b = value.as_bytes();
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || *b.last()? != b'Z'
    {
        return None;
    }
    for (index, byte) in b.iter().enumerate() {
        if matches!(index, 4 | 7 | 10 | 13 | 16)
            || index == b.len() - 1
            || (b.len() > 20 && index == 19)
        {
            continue;
        }
        if !byte.is_ascii_digit() {
            return None;
        }
    }
    if b.len() > 20 && (b[19] != b'.' || b.len() > 30 || b.len() < 22) {
        return None;
    }
    let part = |range: std::ops::Range<usize>| -> Option<u32> {
        std::str::from_utf8(&b[range]).ok()?.parse().ok()
    };
    let year = part(0..4)?;
    let month = part(5..7)?;
    let day = part(8..10)?;
    let hour = part(11..13)?;
    let minute = part(14..16)?;
    let second = part(17..19)?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let nanos = if b.len() > 20 {
        let digits = &value[20..value.len() - 1];
        let parsed: u32 = digits.parse().ok()?;
        parsed * 10u32.pow(9 - digits.len() as u32)
    } else {
        0
    };
    Some(UtcInstant {
        year,
        month,
        day,
        hour,
        minute,
        second,
        nanos,
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ` for unix seconds (proleptic Gregorian, UTC).
pub fn format_utc(unix_seconds: u64) -> String {
    let days = (unix_seconds / 86_400) as i64;
    let secs = unix_seconds % 86_400;
    // Civil-from-days (Howard Hinnant), the inverse of `unix_seconds`.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    )
}

/// Seconds since the Unix epoch now.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Unix seconds of a UTC timestamp, or `None` when it does not parse.
pub fn utc_unix_seconds(value: &str) -> Option<i64> {
    Some(parse_utc(value)?.unix_seconds())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_orders() {
        assert_eq!(utc_unix_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(utc_unix_seconds("2000-03-01T00:00:00Z"), Some(951_868_800));
        let a = parse_utc("2026-09-23T09:00:00.5Z").unwrap();
        let b = parse_utc("2026-09-23T09:00:00.500000001Z").unwrap();
        assert_eq!(a.nanos, 500_000_000);
        assert!(a < b);
    }

    #[test]
    fn format_round_trips() {
        for value in [0u64, 951_868_800, 1_709_164_800, 1_790_000_000, 4_102_444_799] {
            let text = format_utc(value);
            assert_eq!(utc_unix_seconds(&text), Some(value as i64), "{text}");
        }
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_868_800), "2000-03-01T00:00:00Z");
    }

    #[test]
    fn rejects_invalid() {
        for bad in [
            "2026-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01 00:00:00Z",
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00.1234567890Z",
            "0000-01-01T00:00:00Z",
        ] {
            assert!(parse_utc(bad).is_none(), "{bad}");
        }
        assert!(parse_utc("2024-02-29T00:00:00Z").is_some());
    }
}
