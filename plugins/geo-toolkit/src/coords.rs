//! Coordinate parsing and formatting: decimal degrees, degrees-minutes(-seconds), UTM, MGRS, geohash, Plus Codes (Open
//! Location Code) and Maidenhead locators. All offline maths. UTM uses the Krueger series (Karney 2011), accurate to
//! nanometres inside a zone.

use std::f64::consts::PI;

pub const A: f64 = 6_378_137.0;
pub const F: f64 = 1.0 / 298.257_223_563;
const K0: f64 = 0.9996;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LL {
    pub lat: f64,
    pub lon: f64,
}

pub fn check(lat: f64, lon: f64) -> Result<LL, String> {
    if !lat.is_finite() || !lon.is_finite() || lat.abs() > 90.0 || lon.abs() > 180.0 {
        return Err(format!("coordinates out of range (latitude -90..90, longitude -180..180): {lat}, {lon}"));
    }
    Ok(LL { lat, lon })
}

// ---- UTM -----------------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Utm {
    pub zone: u32,
    pub band: char,
    pub north: bool,
    pub easting: f64,
    pub northing: f64,
}

const BANDS: &str = "CDEFGHJKLMNPQRSTUVWX";

pub fn band_for(lat: f64) -> Option<char> {
    if !(-80.0..=84.0).contains(&lat) {
        return None;
    }
    BANDS.chars().nth((((lat + 80.0) / 8.0).floor() as usize).min(19))
}

pub fn zone_for(lat: f64, lon: f64) -> u32 {
    let mut z = (((lon + 180.0) / 6.0).floor() as i64 % 60 + 1) as u32;
    if (56.0..64.0).contains(&lat) && (3.0..12.0).contains(&lon) {
        z = 32;
    }
    if (72.0..=84.0).contains(&lat) {
        z = match lon {
            l if (0.0..9.0).contains(&l) => 31,
            l if (9.0..21.0).contains(&l) => 33,
            l if (21.0..33.0).contains(&l) => 35,
            l if (33.0..42.0).contains(&l) => 37,
            _ => z,
        };
    }
    z
}

fn series() -> (f64, [f64; 4], [f64; 4], [f64; 4], f64) {
    let n = F / (2.0 - F);
    let (n2, n3, n4) = (n * n, n * n * n, n.powi(4));
    let a_ = A / (1.0 + n) * (1.0 + n2 / 4.0 + n4 / 64.0);
    let alpha = [n / 2.0 - 2.0 * n2 / 3.0 + 5.0 * n3 / 16.0 + 41.0 * n4 / 180.0, 13.0 * n2 / 48.0 - 3.0 * n3 / 5.0 + 557.0 * n4 / 1440.0, 61.0 * n3 / 240.0 - 103.0 * n4 / 140.0, 49561.0 * n4 / 161280.0];
    let beta = [n / 2.0 - 2.0 * n2 / 3.0 + 37.0 * n3 / 96.0 - n4 / 360.0, n2 / 48.0 + n3 / 15.0 - 437.0 * n4 / 1440.0, 17.0 * n3 / 480.0 - 37.0 * n4 / 840.0, 4397.0 * n4 / 161280.0];
    let delta = [2.0 * n - 2.0 * n2 / 3.0 - 2.0 * n3 + 116.0 * n4 / 45.0, 7.0 * n2 / 3.0 - 8.0 * n3 / 5.0 - 227.0 * n4 / 45.0, 56.0 * n3 / 15.0 - 136.0 * n4 / 35.0, 4279.0 * n4 / 630.0];
    (a_, alpha, beta, delta, n)
}

fn forward_tm(lat: f64, dlon: f64) -> (f64, f64) {
    let (a_, alpha, _, _, n) = series();
    let (phi, dl) = (lat.to_radians(), dlon.to_radians());
    let c = 2.0 * n.sqrt() / (1.0 + n);
    let t = (phi.sin().atanh() - c * (c * phi.sin()).atanh()).sinh();
    let xi0 = t.atan2(dl.cos());
    let eta0 = (dl.sin() / (1.0 + t * t).sqrt()).atanh();
    let (mut xi, mut eta) = (xi0, eta0);
    for (j, a) in alpha.iter().enumerate() {
        let k = 2.0 * (j as f64 + 1.0);
        xi += a * (k * xi0).sin() * (k * eta0).cosh();
        eta += a * (k * xi0).cos() * (k * eta0).sinh();
    }
    (K0 * a_ * eta, K0 * a_ * xi)
}

pub fn to_utm(p: LL) -> Option<Utm> {
    let band = band_for(p.lat)?;
    let zone = zone_for(p.lat, p.lon);
    let cm = (zone as f64 - 1.0) * 6.0 - 180.0 + 3.0;
    let (x, y) = forward_tm(p.lat, p.lon - cm);
    let north = p.lat >= 0.0;
    Some(Utm { zone, band, north, easting: 500_000.0 + x, northing: if north { y } else { 10_000_000.0 + y } })
}

pub fn from_utm(u: &Utm) -> Result<LL, String> {
    if !(1..=60).contains(&u.zone) {
        return Err("UTM zone must be 1..60".into());
    }
    if !(100_000.0..900_000.0).contains(&u.easting) {
        return Err("UTM easting must be between 100000 and 900000".into());
    }
    if !(0.0..=10_000_000.0).contains(&u.northing) {
        return Err("UTM northing must be between 0 and 10000000".into());
    }
    let (a_, _, beta, delta, _) = series();
    let y = if u.north { u.northing } else { u.northing - 10_000_000.0 };
    let (xi, eta) = (y / (K0 * a_), (u.easting - 500_000.0) / (K0 * a_));
    let (mut xi2, mut eta2) = (xi, eta);
    for (j, b) in beta.iter().enumerate() {
        let k = 2.0 * (j as f64 + 1.0);
        xi2 -= b * (k * xi).sin() * (k * eta).cosh();
        eta2 -= b * (k * xi).cos() * (k * eta).sinh();
    }
    let chi = (xi2.sin() / eta2.cosh()).asin();
    let mut phi = chi;
    for (j, d) in delta.iter().enumerate() {
        phi += d * (2.0 * (j as f64 + 1.0) * chi).sin();
    }
    let cm = (u.zone as f64 - 1.0) * 6.0 - 180.0 + 3.0;
    let lon = cm + eta2.sinh().atan2(xi2.cos()).to_degrees();
    check(phi.to_degrees(), lon)
}

impl Utm {
    pub fn text(&self) -> String {
        format!("{}{} {:.0} {:.0}", self.zone, self.band, self.easting, self.northing)
    }
}

// ---- MGRS ----------------------------------------------------------------------------------------------------------------

const COL_SETS: [&str; 3] = ["ABCDEFGH", "JKLMNPQR", "STUVWXYZ"];
const ROW_LETTERS: &str = "ABCDEFGHJKLMNPQRSTUV";

/// MGRS string with `digits` per axis (5 = 1 m, 1 = 10 km).
pub fn to_mgrs(p: LL, digits: usize) -> Option<String> {
    let u = to_utm(p)?;
    let col = COL_SETS[((u.zone - 1) % 3) as usize].chars().nth((u.easting / 100_000.0).floor() as usize - 1)?;
    let mut row_idx = ((u.northing / 100_000.0).floor() as usize) % 20;
    if u.zone % 2 == 0 {
        row_idx = (row_idx + 5) % 20;
    }
    let row = ROW_LETTERS.chars().nth(row_idx)?;
    let div = 10f64.powi(5 - digits as i32);
    let e = ((u.easting % 100_000.0) / div).floor() as u64;
    let n = ((u.northing % 100_000.0) / div).floor() as u64;
    Some(format!("{}{}{}{}{:0w$}{:0w$}", u.zone, u.band, col, row, e, n, w = digits))
}

pub fn from_mgrs(s: &str) -> Result<LL, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    let zlen = s.chars().take_while(char::is_ascii_digit).count();
    if !(1..=2).contains(&zlen) || s.len() < zlen + 3 {
        return Err("not an MGRS reference".into());
    }
    let zone: u32 = s[..zlen].parse().map_err(|_| "bad MGRS zone")?;
    let mut it = s[zlen..].chars();
    let (band, col, row) = (it.next().unwrap(), it.next().ok_or("short MGRS")?, it.next().ok_or("short MGRS")?);
    let digits: String = it.collect();
    if !(1..=60).contains(&zone) || !BANDS.contains(band) || !digits.chars().all(|c| c.is_ascii_digit()) || digits.len() % 2 != 0 || digits.len() > 10 {
        return Err("not an MGRS reference".into());
    }
    let ci = COL_SETS[((zone - 1) % 3) as usize].find(col).ok_or("invalid MGRS column letter for this zone")?;
    let mut ri = ROW_LETTERS.find(row).ok_or("invalid MGRS row letter")?;
    if zone % 2 == 0 {
        ri = (ri + 20 - 5) % 20;
    }
    let half = digits.len() / 2;
    let scale = 10f64.powi(5 - half as i32);
    let (e_in, n_in) = if half == 0 { (0.0, 0.0) } else { (digits[..half].parse::<f64>().unwrap() * scale, digits[half..].parse::<f64>().unwrap() * scale) };
    let easting = (ci as f64 + 1.0) * 100_000.0 + e_in;
    // The row letter repeats every 2000 km: take the first northing that is inside the latitude band.
    let band_south = (BANDS.find(band).unwrap() as f64) * 8.0 - 80.0;
    let cm = (zone as f64 - 1.0) * 6.0 - 180.0 + 3.0;
    let south_n = to_utm(LL { lat: band_south.max(-80.0), lon: cm }).map(|u| u.northing).ok_or("band outside UTM")?;
    let mut northing = ri as f64 * 100_000.0 + n_in;
    while northing < south_n - 60_000.0 {
        northing += 2_000_000.0;
    }
    from_utm(&Utm { zone, band, north: band >= 'N', easting, northing })
}

// ---- Geohash -------------------------------------------------------------------------------------------------------------

const B32: &[u8] = b"0123456789bcdefghjkmnpqrstuvwxyz";

pub fn to_geohash(p: LL, len: usize) -> String {
    let (mut lat, mut lon) = ((-90.0, 90.0), (-180.0, 180.0));
    let (mut bits, mut ch, mut even) = (0, 0usize, true);
    let mut out = String::new();
    while out.len() < len {
        let (rng, v) = if even { (&mut lon, p.lon) } else { (&mut lat, p.lat) };
        let mid = (rng.0 + rng.1) / 2.0;
        ch <<= 1;
        if v >= mid {
            ch |= 1;
            rng.0 = mid;
        } else {
            rng.1 = mid;
        }
        even = !even;
        bits += 1;
        if bits == 5 {
            out.push(B32[ch] as char);
            bits = 0;
            ch = 0;
        }
    }
    out
}

/// (centre, (south, west, north, east))
pub fn from_geohash(s: &str) -> Result<(LL, [f64; 4]), String> {
    let s = s.trim().to_ascii_lowercase();
    if s.is_empty() || s.len() > 12 {
        return Err("geohash must be 1 to 12 characters".into());
    }
    let (mut lat, mut lon) = ((-90.0, 90.0), (-180.0, 180.0));
    let mut even = true;
    for c in s.bytes() {
        let v = B32.iter().position(|&b| b == c).ok_or("invalid geohash character")?;
        for i in (0..5).rev() {
            let rng = if even { &mut lon } else { &mut lat };
            let mid = (rng.0 + rng.1) / 2.0;
            if (v >> i) & 1 == 1 { rng.0 = mid } else { rng.1 = mid }
            even = !even;
        }
    }
    Ok((LL { lat: (lat.0 + lat.1) / 2.0, lon: (lon.0 + lon.1) / 2.0 }, [lat.0, lon.0, lat.1, lon.1]))
}

pub fn geohash_neighbours(p: LL, len: usize) -> Vec<String> {
    let (_, b) = from_geohash(&to_geohash(p, len)).unwrap();
    let (dh, dw) = (b[2] - b[0], b[3] - b[1]);
    let c = LL { lat: (b[0] + b[2]) / 2.0, lon: (b[1] + b[3]) / 2.0 };
    let mut out = vec![];
    for dy in [1.0, 0.0, -1.0] {
        for dx in [-1.0, 0.0, 1.0] {
            if dx == 0.0 && dy == 0.0 {
                continue;
            }
            let (la, lo) = (c.lat + dy * dh, (c.lon + dx * dw + 540.0).rem_euclid(360.0) - 180.0);
            if la.abs() <= 90.0 {
                out.push(to_geohash(LL { lat: la, lon: lo }, len));
            }
        }
    }
    out
}

// ---- Plus Codes ----------------------------------------------------------------------------------------------------------

const OLC: &[u8] = b"23456789CFGHJMPQRVWX";

pub fn to_pluscode(p: LL, len: usize) -> String {
    let len = len.clamp(2, 15);
    let len = if len < 10 && len % 2 == 1 { len - 1 } else { len }.max(2);
    let lat = (p.lat + 90.0).min(180.0 - 1e-9);
    let lon = (p.lon + 180.0).rem_euclid(360.0);
    // Work in integer units of the finest resolution (1/8000 degree for pairs, then the 4x5 grid refinement).
    let mut lat_i = (lat * 8000.0 * 3125.0 + 1e-6).floor() as i64; // 8000 * 5^5 steps per degree
    let mut lon_i = (lon * 8000.0 * 1024.0 + 1e-6).floor() as i64; // 8000 * 4^5 steps per degree
    let mut grid = vec![];
    for _ in 0..5 {
        let (r, c) = (lat_i % 5, lon_i % 4);
        grid.push(OLC[(r * 4 + c) as usize] as char);
        lat_i /= 5;
        lon_i /= 4;
    }
    grid.reverse();
    let mut pairs = vec![];
    for _ in 0..5 {
        pairs.push((OLC[(lat_i % 20) as usize] as char, OLC[(lon_i % 20) as usize] as char));
        lat_i /= 20;
        lon_i /= 20;
    }
    pairs.reverse();
    let mut full = String::new();
    for (a, b) in &pairs {
        full.push(*a);
        full.push(*b);
    }
    let mut digits: Vec<char> = full.chars().collect();
    digits.extend(grid);
    digits.truncate(len);
    let mut out = String::new();
    for (i, c) in digits.iter().enumerate() {
        if i == 8 {
            out.push('+');
        }
        out.push(*c);
    }
    if len < 8 {
        while out.len() < 8 {
            out.push('0');
        }
        out.push('+');
    } else if len == 8 {
        out.push('+');
    }
    out
}

pub fn is_pluscode(s: &str) -> bool {
    let s = s.trim().to_ascii_uppercase();
    let Some((a, b)) = s.split_once('+') else { return false };
    a.len() <= 8 && a.len() % 2 == 0 && b.len() <= 7 && b.len() != 1 && a.bytes().chain(b.bytes()).all(|c| OLC.contains(&c) || c == b'0') && !b.contains('0')
}

/// Decodes a full code. Returns the centre and the (south, west, north, east) box.
pub fn from_pluscode(s: &str) -> Result<(LL, [f64; 4]), String> {
    let s = s.trim().to_ascii_uppercase();
    if !is_pluscode(&s) {
        return Err("not a Plus Code".into());
    }
    let (a, b) = s.split_once('+').unwrap();
    if a.len() < 8 {
        if a.contains('0') {
            // padded full code, fine
        } else {
            return Err("short Plus Code: give a reference location (ref) to recover it".into());
        }
    }
    let digits: Vec<usize> = a.bytes().chain(b.bytes()).filter(|&c| c != b'0').map(|c| OLC.iter().position(|&x| x == c).unwrap()).collect();
    let (mut lat, mut lon) = (-90.0, -180.0);
    let pair_digits = digits.len().min(10);
    if pair_digits < 2 {
        return Err("Plus Code too short".into());
    }
    let mut size = 20.0;
    for i in 0..pair_digits / 2 {
        if i > 0 {
            size /= 20.0;
        }
        lat += digits[2 * i] as f64 * size;
        lon += digits[2 * i + 1] as f64 * size;
    }
    let (mut hlat, mut hlon) = (size, size);
    for &d in digits.iter().skip(10) {
        hlat /= 5.0;
        hlon /= 4.0;
        lat += (d / 4) as f64 * hlat;
        lon += (d % 4) as f64 * hlon;
    }
    let (n, e) = (lat + hlat, lon + hlon);
    Ok((LL { lat: (lat + n) / 2.0, lon: (lon + e) / 2.0 }, [lat, lon, n, e]))
}

/// Recovers a short code (`WC2R+JW`) near a reference point.
pub fn recover_pluscode(short: &str, reference: LL) -> Result<LL, String> {
    let s = short.trim().to_ascii_uppercase();
    let (a, b) = s.split_once('+').ok_or("not a Plus Code")?;
    if a.len() >= 8 || a.len() % 2 != 0 {
        return Err("not a short Plus Code".into());
    }
    let pad = 8 - a.len();
    let res = 20f64.powi(2 - (pad as i32 / 2)); // size of the first missing pair
    let ref_code = to_pluscode(reference, 8);
    let full = format!("{}{}+{}", &ref_code[..pad], a, b);
    let (c, bx) = from_pluscode(&full)?;
    let half = res / 2.0;
    let (mut lat, mut lon) = (c.lat, c.lon);
    if lat + half < reference.lat && lat + res <= 90.0 { lat += res } else if lat - half > reference.lat && lat - res >= -90.0 { lat -= res }
    if lon + half < reference.lon { lon += res } else if lon - half > reference.lon { lon -= res }
    let _ = bx;
    check(lat, (lon + 540.0).rem_euclid(360.0) - 180.0)
}

// ---- Maidenhead ----------------------------------------------------------------------------------------------------------

pub fn to_maidenhead(p: LL, pairs: usize) -> String {
    let (mut lon, mut lat) = (p.lon + 180.0, p.lat + 90.0);
    let mut out = String::new();
    let (mut dl, mut dt) = (20.0, 10.0);
    for i in 0..pairs.clamp(1, 4) {
        let (a, b) = ((lon / dl).floor().clamp(0.0, 23.0) as u8, (lat / dt).floor().clamp(0.0, 23.0) as u8);
        match i {
            0 => { out.push((b'A' + a) as char); out.push((b'A' + b) as char); }
            1 | 3 => { out.push((b'0' + a.min(9)) as char); out.push((b'0' + b.min(9)) as char); }
            _ => { out.push((b'a' + a) as char); out.push((b'a' + b) as char); }
        }
        lon -= a as f64 * dl;
        lat -= b as f64 * dt;
        let div = match i { 0 => 10.0, 1 => 24.0, _ => 10.0 };
        dl /= div;
        dt /= div;
    }
    out
}

pub fn from_maidenhead(s: &str) -> Result<LL, String> {
    let c: Vec<char> = s.trim().chars().collect();
    if c.len() < 4 || c.len() % 2 != 0 || c.len() > 8 {
        return Err("not a Maidenhead locator".into());
    }
    let (mut lon, mut lat) = (-180.0, -90.0);
    let (mut dl, mut dt) = (20.0, 10.0);
    for (i, pair) in c.chunks(2).enumerate() {
        let val = |ch: char| -> Result<f64, String> {
            match i {
                0 => { let u = ch.to_ascii_uppercase(); if ('A'..='R').contains(&u) { Ok((u as u8 - b'A') as f64) } else { Err("bad field letter".into()) } }
                1 | 3 => ch.to_digit(10).map(|d| d as f64).ok_or_else(|| "bad digit".to_string()),
                _ => { let u = ch.to_ascii_lowercase(); if ('a'..='x').contains(&u) { Ok((u as u8 - b'a') as f64) } else { Err("bad subsquare letter".into()) } }
            }
        };
        lon += val(pair[0])? * dl;
        lat += val(pair[1])? * dt;
        if i < 3 {
            let div = match i { 0 => 10.0, 1 => 24.0, _ => 10.0 };
            dl /= div;
            dt /= div;
        }
        if i == c.len() / 2 - 1 {
            lon += dl * if i == 0 { 10.0 } else { 1.0 } / if i == 0 { 10.0 } else { 1.0 } / 2.0;
            lat += dt / 2.0;
        }
    }
    check(lat, lon)
}

// ---- degrees, minutes, seconds -----------------------------------------------------------------------------------------

pub fn fmt_dms(v: f64, pos: char, neg: char, seconds: bool) -> String {
    let h = if v < 0.0 { neg } else { pos };
    let a = v.abs();
    if seconds {
        let total = (a * 3600.0 * 100.0).round() / 100.0;
        let d = (total / 3600.0).floor();
        let m = ((total - d * 3600.0) / 60.0).floor();
        let s = total - d * 3600.0 - m * 60.0;
        format!("{d:.0}° {m:02.0}′ {s:05.2}″ {h}")
    } else {
        let total = (a * 60.0 * 1000.0).round() / 1000.0;
        let d = (total / 60.0).floor();
        format!("{d:.0}° {:06.3}′ {h}", total - d * 60.0)
    }
}

/// One angle: decimal, "D M", "D M S", with symbols and an optional N/S/E/W letter (before or after).
pub fn parse_angle(s: &str) -> Result<(f64, Option<char>), String> {
    let mut t: String = s.chars().map(|c| match c { '°' | 'º' | '˚' | '′' | '’' | '‘' | '″' | '”' | '"' | '\'' | '′' => ' ', ',' => '.', c => c }).collect();
    t = t.trim().to_string();
    let mut hemi = None;
    let upper = t.to_ascii_uppercase();
    for (i, c) in upper.char_indices() {
        if "NSEW".contains(c) {
            let before_ok = upper[..i].trim().is_empty();
            let after_ok = upper[i + 1..].trim().is_empty();
            if (before_ok || after_ok) && hemi.is_none() {
                hemi = Some(c);
                t = format!("{} {}", &t[..i], &t[i + 1..]);
                break;
            }
        }
    }
    let nums: Vec<&str> = t.split_whitespace().collect();
    if nums.is_empty() || nums.len() > 3 {
        return Err(format!("cannot read '{}' as an angle", s.trim()));
    }
    let mut vals = vec![];
    for n in &nums {
        vals.push(n.parse::<f64>().map_err(|_| format!("cannot read '{}' as an angle", s.trim()))?);
    }
    if vals.len() > 1 && (vals[1] < 0.0 || vals[1] >= 60.0 || vals.get(2).is_some_and(|x| *x < 0.0 || *x >= 60.0)) {
        return Err("minutes and seconds must be below 60".into());
    }
    let neg = nums[0].starts_with('-');
    let mut v = vals[0].abs() + vals.get(1).copied().unwrap_or(0.0) / 60.0 + vals.get(2).copied().unwrap_or(0.0) / 3600.0;
    if neg {
        v = -v;
    }
    if matches!(hemi, Some('S' | 'W')) {
        v = -v.abs();
    } else if hemi.is_some() {
        v = v.abs();
    }
    Ok((v, hemi))
}

fn assemble(a: (f64, Option<char>), b: (f64, Option<char>), lonlat: bool) -> Result<LL, String> {
    let is_lat = |h: Option<char>| matches!(h, Some('N' | 'S'));
    let is_lon = |h: Option<char>| matches!(h, Some('E' | 'W'));
    let (lat, lon) = if is_lat(a.1) || is_lon(b.1) {
        (a.0, b.0)
    } else if is_lon(a.1) || is_lat(b.1) {
        (b.0, a.0)
    } else if lonlat {
        (b.0, a.0)
    } else {
        (a.0, b.0)
    };
    if (is_lat(a.1) && is_lat(b.1)) || (is_lon(a.1) && is_lon(b.1)) {
        return Err("two latitudes or two longitudes given".into());
    }
    check(lat, lon)
}

/// "48.8584, 2.2945", "48°51'30\"N 2°17'40\"E", "N 48 51.5 E 2 17.7", "2.29E 48.85N", "48.8584 2.2945".
pub fn parse_pair(s: &str, lonlat: bool) -> Result<LL, String> {
    let s = s.trim().trim_start_matches(|c: char| c == '(' || c == '[').trim_end_matches(|c: char| c == ')' || c == ']').trim();
    let seps: Vec<usize> = s.char_indices().filter(|(_, c)| *c == ',' || *c == ';' || *c == '/' || *c == '|').map(|(i, _)| i).collect();
    // A comma may be a decimal comma ("48,8584 2,2945"): only split on it when exactly one separator exists and both halves parse.
    if seps.len() == 1 {
        let (l, r) = (&s[..seps[0]], &s[seps[0] + 1..]);
        if let (Ok(a), Ok(b)) = (parse_angle(l), parse_angle(r)) {
            return assemble(a, b, lonlat);
        }
    }
    // Hemisphere letters as delimiters: "N48 51 30 E2 17 40" or "48 51 30 N 2 17 40 E".
    let up = s.to_ascii_uppercase();
    let letters: Vec<(usize, char)> = up.char_indices().filter(|(_, c)| "NSEW".contains(*c)).collect();
    if letters.len() == 2 {
        let (i1, i2) = (letters[0].0, letters[1].0);
        let (first, second) = if s[..i1].trim().is_empty() { (&s[..i2], &s[i2..]) } else { (&s[..=i1], &s[i1 + 1..]) };
        if let (Ok(a), Ok(b)) = (parse_angle(first), parse_angle(second)) {
            return assemble(a, b, lonlat);
        }
    }
    // Plain numbers: 2, 4 or 6 values.
    let cleaned: String = s.chars().map(|c| if matches!(c, '°' | 'º' | '′' | '’' | '″' | '”' | '"' | '\'') { ' ' } else { c }).collect();
    let toks: Vec<&str> = cleaned.split_whitespace().collect();
    let n = toks.len();
    if n == 2 || n == 4 || n == 6 {
        let k = n / 2;
        let (l, r) = (toks[..k].join(" "), toks[k..].join(" "));
        if let (Ok(a), Ok(b)) = (parse_angle(&l), parse_angle(&r)) {
            return assemble(a, b, lonlat);
        }
    }
    Err("could not read this as a coordinate pair".into())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub ll: LL,
    pub kind: &'static str,
    pub bbox: Option<[f64; 4]>,
}

fn regex_utm(s: &str) -> Option<Utm> {
    use regex::Regex;
    let re = Regex::new(r"(?i)^\s*(\d{1,2})\s*([C-HJ-NP-X]|N|S)\s+(\d{5,7}(?:\.\d+)?)\s*(?:m\s*)?E?[\s,;]+(\d{1,8}(?:\.\d+)?)\s*(?:m\s*)?N?\s*$").ok()?;
    let c = re.captures(s)?;
    let zone: u32 = c[1].parse().ok()?;
    let letter = c[2].to_ascii_uppercase().chars().next()?;
    let north = letter >= 'N';
    let band = if BANDS.contains(letter) && letter != 'N' && letter != 'S' || (letter != 'N' && letter != 'S') { letter } else if north { 'N' } else { 'M' };
    Some(Utm { zone, band, north, easting: c[3].parse().ok()?, northing: c[4].parse().ok()? })
}

pub fn parse(input: &str, reference: Option<LL>, lonlat: bool) -> Result<Parsed, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("enter a coordinate".into());
    }
    if s.len() > 200 {
        return Err("input is too long for a single coordinate".into());
    }
    let s2 = s.strip_prefix("geo:").or_else(|| s.strip_prefix("GEO:")).map(|r| r.split(';').next().unwrap_or(r)).unwrap_or(s);
    let ok = |ll: LL, kind: &'static str| Ok(Parsed { ll, kind, bbox: None });
    // Plus Code (full or short with a reference).
    let first_word = s2.split_whitespace().next().unwrap_or("");
    if is_pluscode(first_word) {
        let a_len = first_word.split('+').next().map(str::len).unwrap_or(0);
        if a_len == 8 || first_word.contains('0') {
            let (c, bx) = from_pluscode(first_word)?;
            return Ok(Parsed { ll: c, kind: "pluscode", bbox: Some(bx) });
        }
        let r = reference.ok_or("short Plus Code: give a reference location (lat, lon) to recover it")?;
        return recover_pluscode(first_word, r).and_then(|ll| ok(ll, "pluscode-short"));
    }
    // UTM, then MGRS.
    if let Some(u) = regex_utm(s2) {
        return from_utm(&u).and_then(|ll| ok(ll, "utm"));
    }
    let squashed: String = s2.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_ascii_uppercase();
    let mg = regex::Regex::new(r"^\d{1,2}[C-HJ-NP-X][A-HJ-NP-Z]{2}(\d{2}|\d{4}|\d{6}|\d{8}|\d{10})?$").unwrap();
    if mg.is_match(&squashed) {
        return from_mgrs(&squashed).and_then(|ll| ok(ll, "mgrs"));
    }
    // Decimal, DM, DMS.
    match parse_pair(s2, lonlat) {
        Ok(ll) => return ok(ll, if s2.contains(['°', '′', '\'', '"', '″']) { "dms" } else { "decimal" }),
        Err(e) if s2.chars().any(|c| c.is_ascii_digit()) && s2.chars().any(|c| c.is_whitespace() || c == ',') && !s2.chars().all(|c| c.is_ascii_alphanumeric()) => {
            if !(s2.len() < 13 && s2.chars().all(|c| c.is_ascii_alphanumeric())) {
                return Err(e);
            }
        }
        Err(_) => {}
    }
    // Maidenhead, then geohash (single tokens only).
    let tok = s2.trim();
    if tok.chars().all(|c| c.is_ascii_alphanumeric()) {
        let mh = regex::Regex::new(r"^[A-Ra-r]{2}\d{2}([A-Xa-x]{2}(\d{2}([A-Xa-x]{2})?)?)?$").unwrap();
        let upper_start = tok.chars().take(2).all(|c| c.is_ascii_uppercase());
        if mh.is_match(tok) && (tok.len() >= 6 || upper_start) {
            return from_maidenhead(tok).and_then(|ll| ok(ll, "maidenhead"));
        }
        if tok.len() >= 3 && tok.bytes().all(|b| B32.contains(&b.to_ascii_lowercase())) && tok.chars().any(|c| c.is_ascii_alphabetic()) {
            let (c, bx) = from_geohash(tok)?;
            return Ok(Parsed { ll: c, kind: "geohash", bbox: Some(bx) });
        }
    }
    Err("not recognised: try decimal degrees, DMS, UTM, MGRS, geohash, a Plus Code or a Maidenhead locator".into())
}

/// Web Mercator (EPSG:3857) metres.
pub fn web_mercator(p: LL) -> Option<(f64, f64)> {
    (p.lat.abs() <= 85.051_128_78).then(|| (A * p.lon.to_radians(), A * (PI / 4.0 + p.lat.to_radians() / 2.0).tan().ln()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64, tol: f64) {
        assert!((a - b).abs() < tol, "{a} vs {b}");
    }

    #[test]
    fn utm_known_values() {
        // On the central meridian of zone 31 at the equator: E 500000, N 0.
        let u = to_utm(LL { lat: 0.0, lon: 3.0 }).unwrap();
        close(u.easting, 500_000.0, 1e-6);
        close(u.northing, 0.0, 1e-6);
        // 45 N on the central meridian: k0 * meridian arc length (4984944.378 m on GRS80).
        let u = to_utm(LL { lat: 45.0, lon: 3.0 }).unwrap();
        close(u.northing, 0.9996 * 4_984_944.378, 0.05);
        assert_eq!((u.zone, u.band), (31, 'T'));
        // Eiffel Tower (48.8583701 N, 2.2944813 E): E 448250.6, N 5411951.6.
        let u = to_utm(LL { lat: 48.8583701, lon: 2.2944813 }).unwrap();
        assert_eq!((u.zone, u.band), (31, 'U'));
        close(u.easting, 448_251.0, 1.5);
        close(u.northing, 5_411_951.6, 0.5); // cross-checked against Snyder's series
    }

    #[test]
    fn utm_round_trip_everywhere() {
        for (lat, lon) in [(0.0, 0.0), (48.85, 2.29), (-33.86, 151.21), (-77.85, 166.67), (83.9, 20.0), (60.0, 5.0), (78.2, 15.6), (1.28, 103.85), (64.0, -21.9)] {
            let u = to_utm(LL { lat, lon }).unwrap();
            let r = from_utm(&u).unwrap();
            close(r.lat, lat, 1e-8);
            close(r.lon, lon, 1e-8);
        }
        assert!(to_utm(LL { lat: 85.0, lon: 0.0 }).is_none());
        assert!(to_utm(LL { lat: -81.0, lon: 0.0 }).is_none());
    }

    #[test]
    fn utm_zone_exceptions() {
        assert_eq!(zone_for(60.0, 5.0), 32); // Norway
        assert_eq!(zone_for(78.0, 15.0), 33); // Svalbard
        assert_eq!(zone_for(48.0, 2.0), 31);
        assert_eq!(zone_for(-33.0, 151.0), 56);
        assert_eq!(band_for(48.0), Some('U'));
        assert_eq!(band_for(-33.0), Some('H'));
        assert_eq!(band_for(84.0), Some('X'));
    }

    #[test]
    fn mgrs_known_and_round_trip() {
        assert_eq!(to_mgrs(LL { lat: 48.8583701, lon: 2.2944813 }, 5).unwrap(), "31UDQ4825011951");
        assert_eq!(to_mgrs(LL { lat: 48.8583701, lon: 2.2944813 }, 3).unwrap(), "31UDQ482119");
        let p = from_mgrs("31U DQ 48250 11951").unwrap();
        close(p.lat, 48.85837, 2e-5);
        close(p.lon, 2.29448, 2e-5);
        for (lat, lon) in [(-33.86, 151.21), (64.14, -21.9), (0.5, 0.5), (-0.5, 100.2), (51.5, -0.12), (-54.8, -68.3)] {
            let m = to_mgrs(LL { lat, lon }, 5).unwrap();
            let r = from_mgrs(&m).unwrap();
            close(r.lat, lat, 2e-5);
            close(r.lon, lon, 2e-5);
        }
        assert!(from_mgrs("31UZZ1234").is_err());
        assert!(from_mgrs("nonsense").is_err());
    }

    #[test]
    fn geohash_known() {
        assert_eq!(to_geohash(LL { lat: 57.64911, lon: 10.40744 }, 11), "u4pruydqqvj");
        let (c, bx) = from_geohash("u4pruydqqvj").unwrap();
        close(c.lat, 57.64911, 1e-5);
        close(c.lon, 10.40744, 1e-5);
        assert!(bx[0] < c.lat && c.lat < bx[2]);
        assert!(from_geohash("a").is_err()); // 'a' is not in the alphabet
        assert_eq!(geohash_neighbours(LL { lat: 57.64911, lon: 10.40744 }, 6).len(), 8);
    }

    #[test]
    fn pluscode_known_and_round_trip() {
        assert_eq!(to_pluscode(LL { lat: 20.375, lon: 2.775 }, 6), "7FG49Q00+");
        let (c, bx) = from_pluscode("7FG49Q00+").unwrap();
        close(c.lat, 20.375, 1e-9);
        close(c.lon, 2.775, 1e-9);
        close(bx[2] - bx[0], 0.05, 1e-9);
        // Official test vector: 20.3701125, 2.782234375 -> 7FG49QCJ+2VX (11 digits).
        assert_eq!(to_pluscode(LL { lat: 20.3701125, lon: 2.782234375 }, 11), "7FG49QCJ+2VX");
        for (lat, lon) in [(47.365590, 8.524997), (-33.8568, 151.2153), (0.0, 0.0), (89.9, 179.9), (-89.9, -179.9)] {
            let code = to_pluscode(LL { lat, lon }, 10);
            let (c, bx) = from_pluscode(&code).unwrap();
            assert!(bx[0] <= lat && lat <= bx[2] && bx[1] <= lon && lon <= bx[3], "{code}");
            close(c.lat, lat, 0.0002);
        }
        assert!(is_pluscode("8FVC9G8F+6W") && !is_pluscode("hello") && !is_pluscode("8FVC9G8F+6"));
    }

    #[test]
    fn short_pluscode_recovery() {
        let full = to_pluscode(LL { lat: 47.365590, lon: 8.524997 }, 10);
        let short = format!("{}", &full[4..]);
        let r = recover_pluscode(&short, LL { lat: 47.3, lon: 8.5 }).unwrap();
        close(r.lat, 47.365590, 0.0002);
        close(r.lon, 8.524997, 0.0002);
    }

    #[test]
    fn maidenhead() {
        assert_eq!(to_maidenhead(LL { lat: 48.8584, lon: 2.2945 }, 3), "JN18du");
        let p = from_maidenhead("JN18du").unwrap();
        close(p.lat, 48.8584, 0.03);
        close(p.lon, 2.2945, 0.05);
        assert!(from_maidenhead("ZZ99").is_err());
    }

    #[test]
    fn dms_formatting() {
        assert_eq!(fmt_dms(48.858333, 'N', 'S', true), "48° 51′ 30.00″ N");
        assert_eq!(fmt_dms(-2.2945, 'E', 'W', false), "2° 17.670′ W");
    }

    #[test]
    fn parse_many_pair_formats() {
        let want = LL { lat: 48.858333, lon: 2.294444 };
        for s in ["48.858333, 2.294444", "48.858333 2.294444", "48°51'30\"N 2°17'40\"E", "N 48 51 30 E 2 17 40", "48 51 30 N, 2 17 40 E", "2°17'40\"E 48°51'30\"N", "48.858333N 2.294444E", "48° 51.5' N, 2° 17.667' E", "geo:48.858333,2.294444", "(48.858333, 2.294444)", "48,858333 2,294444"] {
            let p = parse(s, None, false).unwrap_or_else(|e| panic!("{s}: {e}"));
            close(p.ll.lat, want.lat, 1e-4);
            close(p.ll.lon, want.lon, 1e-4);
        }
        let p = parse("-33.86, 151.21", None, false).unwrap().ll;
        assert!(p.lat < 0.0 && p.lon > 0.0);
        let p = parse("33.86S 151.21W", None, false).unwrap().ll;
        assert!(p.lat < 0.0 && p.lon < 0.0);
        let p = parse("2.29, 48.85", None, true).unwrap().ll;
        close(p.lat, 48.85, 1e-9);
    }

    #[test]
    fn parse_other_kinds() {
        assert_eq!(parse("31U 448251 5411932", None, false).unwrap().kind, "utm");
        assert_eq!(parse("31U DQ 48251 11932", None, false).unwrap().kind, "mgrs");
        assert_eq!(parse("u4pruydqqvj", None, false).unwrap().kind, "geohash");
        assert_eq!(parse("8FW4V75V+8Q", None, false).unwrap().kind, "pluscode");
        assert_eq!(parse("JN18eu", None, false).unwrap().kind, "maidenhead");
        let p = parse("56 N 500000 6000000", None, false).unwrap();
        assert_eq!(p.kind, "utm");
        assert!(parse("V4VQ+JC", None, false).is_err(), "short code without a reference");
        assert!(parse("V4VQ+JC", Some(LL { lat: 47.0, lon: 8.0 }), false).is_ok());
    }

    #[test]
    fn parse_rejects_bad_input() {
        for s in ["", "hello world", "91, 10", "10, 181", "48.8 N, 2.3 N", "12 75 00 N 1 2 3 E", "31U 1 2", "nonsense text 12", &"1".repeat(300)] {
            assert!(parse(s, None, false).is_err(), "{s}");
        }
    }

    #[test]
    fn mercator() {
        let (x, y) = web_mercator(LL { lat: 0.0, lon: 180.0 }).unwrap();
        close(x, 20_037_508.34, 0.01);
        close(y, 0.0, 1e-6);
        assert!(web_mercator(LL { lat: 89.0, lon: 0.0 }).is_none());
    }
}
