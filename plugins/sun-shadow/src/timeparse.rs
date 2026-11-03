//! Small, dependency-free date and time parsing: ISO 8601 with optional offset, plain dates and unix seconds.

pub const MIN_YEAR: i64 = 1800;
pub const MAX_YEAR: i64 = 2300;

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => if is_leap(y) { 29 } else { 28 },
    }
}

/// Parses `YYYY-MM-DD` into unix seconds at 00:00 UTC.
pub fn parse_date(s: &str) -> Result<f64, String> {
    let s = s.trim();
    let mut it = s.split('-');
    let (Some(y), Some(m), Some(d), None) = (it.next(), it.next(), it.next(), it.next()) else { return Err("date must look like 2024-05-02".into()) };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err("date must look like 2024-05-02".into());
    }
    let (y, m, d): (i64, i64, i64) = (y.parse().map_err(|_| "bad year")?, m.parse().map_err(|_| "bad month")?, d.parse().map_err(|_| "bad day")?);
    if !(MIN_YEAR..=MAX_YEAR).contains(&y) {
        return Err(format!("year must be between {MIN_YEAR} and {MAX_YEAR}"));
    }
    if !(1..=12).contains(&m) || d < 1 || d > days_in_month(y, m) {
        return Err("no such calendar date".into());
    }
    Ok((days_from_civil(y, m, d) * 86400) as f64)
}

/// Parses an instant to unix seconds. Accepts `2024-05-02T14:11[:SS[.fff]]` followed by `Z` or `+HH:MM`/`-HH:MM`
/// (no suffix means UTC), a space instead of `T`, or a bare integer of unix seconds.
pub fn parse_time(s: &str) -> Result<f64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("time is required (for example 2024-05-02T14:11:00Z)".into());
    }
    if s.bytes().all(|b| b.is_ascii_digit()) && s.len() >= 9 && s.len() <= 11 {
        return s.parse::<f64>().map_err(|_| "bad unix time".into());
    }
    let (date, rest) = s.split_once(['T', ' ']).ok_or("time must look like 2024-05-02T14:11:00Z")?;
    let base = parse_date(date)?;
    let rest = rest.trim();
    let (clock, offset) = if let Some(c) = rest.strip_suffix(['Z', 'z']) {
        (c, 0.0)
    } else if let Some(i) = rest.rfind(['+', '-']).filter(|&i| i > 0) {
        let (c, o) = rest.split_at(i);
        let sign = if o.starts_with('-') { -1.0 } else { 1.0 };
        let o = &o[1..];
        let (oh, om) = match o.split_once(':') {
            Some((h, m)) => (h, m),
            None if o.len() == 4 => (&o[..2], &o[2..]),
            None if o.len() == 2 => (o, "0"),
            _ => return Err("bad UTC offset".into()),
        };
        let (oh, om): (f64, f64) = (oh.parse().map_err(|_| "bad UTC offset")?, om.parse().map_err(|_| "bad UTC offset")?);
        if oh > 14.0 || om >= 60.0 {
            return Err("UTC offset out of range".into());
        }
        (c, sign * (oh * 3600.0 + om * 60.0))
    } else {
        (rest, 0.0)
    };
    let mut parts = clock.split(':');
    let h: f64 = parts.next().ok_or("missing hour")?.parse().map_err(|_| "bad hour")?;
    let m: f64 = parts.next().ok_or("time needs hours and minutes")?.parse().map_err(|_| "bad minute")?;
    let sec: f64 = parts.next().map(|x| x.parse().map_err(|_| "bad second")).transpose()?.unwrap_or(0.0);
    if parts.next().is_some() || !(0.0..24.0).contains(&h) || !(0.0..60.0).contains(&m) || !(0.0..61.0).contains(&sec) {
        return Err("time of day out of range".into());
    }
    Ok(base + h * 3600.0 + m * 60.0 + sec - offset)
}

/// Formats unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso(unix: f64) -> String {
    let s = unix.round() as i64;
    let (y, m, d) = civil_from_days(s.div_euclid(86400));
    let r = s.rem_euclid(86400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", r / 3600, (r % 3600) / 60, r % 60)
}

pub fn date_string(unix: f64) -> String {
    iso(unix)[..10].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_dates() {
        assert_eq!(parse_time("1970-01-01T00:00:00Z").unwrap(), 0.0);
        assert_eq!(parse_time("2000-01-01T12:00:00Z").unwrap(), 946728000.0);
        assert_eq!(parse_time("2024-02-29 00:00").unwrap(), 1709164800.0);
    }

    #[test]
    fn offsets() {
        let z = parse_time("2024-05-02T12:00:00Z").unwrap();
        assert_eq!(parse_time("2024-05-02T14:00:00+02:00").unwrap(), z);
        assert_eq!(parse_time("2024-05-02T07:00:00-0500").unwrap(), z);
        assert_eq!(parse_time("2024-05-02T12:00").unwrap(), z);
        assert_eq!(parse_time("1714651200").unwrap(), z);
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "yesterday", "2024-13-01T00:00Z", "2023-02-29T00:00Z", "2024-05-02T25:00Z", "2024-05-02T12:61Z", "2024-05-02", "1000-01-01T00:00Z", "2024-05-02T12:00+99:00"] {
            assert!(parse_time(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn iso_round_trip() {
        for s in ["1999-12-31T23:59:59Z", "2024-02-29T00:00:00Z", "1900-03-01T06:07:08Z"] {
            assert_eq!(iso(parse_time(s).unwrap()), s);
        }
        assert_eq!(date_string(86400.0), "1970-01-02");
    }
}
