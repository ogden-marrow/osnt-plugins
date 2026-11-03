//! Parser for readsb "heatmap" files (`heatmap/NN.bin.ttf` in the adsb.lol globe_history tar).
//!
//! The file is one gzip stream. Decompressed it is an index of `num_slices` 16-byte entries (the first int32 of the first
//! entry is `num_slices`), then, for each time slice (10 s apart, 180 per half hour), a marker entry followed by that
//! slice's entries. All entries are 16 bytes little endian: `i32 hex, i32 lat, i32 lon, i16 alt, i16 gs`.
//!   marker:   hex == 0xe7f7c9d, lat/lon = high/low 32 bits of the slice's unix time in ms, alt = interval in ms
//!   callsign: lat >= 1<<30; lat & 0x3FFF = squawk digits as a decimal number, lon+alt+gs bytes = 8-char callsign
//!   position: lat/lon in 1e-6 degrees, alt in 25 ft steps (-123 ground, -124 unknown), gs in 0.1 kt (-1 invalid);
//!             hex = address | addrtype << 27, address bit 24 = non-ICAO (TIS-B etc.)

use std::io::{self, BufReader, Read};

const MARKER: i32 = 0x0e7f_7c9d;

#[derive(Debug, Clone, PartialEq)]
pub enum Rec {
    Slice { ts_ms: i64 },
    Callsign { addr: u32, squawk: u16, callsign: String },
    Pos { addr: u32, lat: i32, lon: i32, alt: i16, gs: i16 },
}

/// Printable identifier: 6 lowercase hex digits, `~` prefix for non-ICAO addresses.
pub fn hex_string(addr: u32) -> String {
    if addr & 0x0100_0000 != 0 { format!("~{:06x}", addr & 0xFF_FFFF) } else { format!("{:06x}", addr & 0xFF_FFFF) }
}

/// Stream the records to `f`; `f` returns false to stop early. Returns Ok even on a clean EOF.
pub fn parse<R: Read>(r: R, mut f: impl FnMut(Rec) -> bool) -> io::Result<()> {
    let mut r = BufReader::with_capacity(1 << 16, r);
    let mut b = [0u8; 16];
    r.read_exact(&mut b)?;
    let n = i32::from_le_bytes(b[0..4].try_into().unwrap());
    if !(1..=100_000).contains(&n) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a readsb heatmap file (bad slice index)"));
    }
    io::copy(&mut r.by_ref().take((n as u64 - 1) * 16), &mut io::sink())?;
    loop {
        match r.read_exact(&mut b) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let hex = i32::from_le_bytes(b[0..4].try_into().unwrap());
        let lat = i32::from_le_bytes(b[4..8].try_into().unwrap());
        let lon = i32::from_le_bytes(b[8..12].try_into().unwrap());
        let rec = if hex == MARKER {
            Rec::Slice { ts_ms: ((lat as i64) << 32) | (lon as u32 as i64) }
        } else if lat >= (1 << 30) {
            let cs: String = b[8..16].iter().take_while(|c| **c != 0).map(|c| *c as char).filter(|c| c.is_ascii_graphic() || *c == ' ').collect();
            Rec::Callsign { addr: hex as u32 & 0x07FF_FFFF, squawk: (lat & 0x3FFF) as u16, callsign: cs.trim().to_string() }
        } else {
            Rec::Pos { addr: hex as u32 & 0x07FF_FFFF, lat, lon, alt: i16::from_le_bytes([b[12], b[13]]), gs: i16::from_le_bytes([b[14], b[15]]) }
        };
        if !f(rec) {
            return Ok(());
        }
    }
}

#[cfg(test)]
pub mod testutil {
    use super::MARKER;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    pub enum E { Pos(u32, f64, f64, i16, i16), Cs(u32, u16, &'static str) }

    /// Build a gzip'd heatmap file: `slices` is a list of (unix seconds, entries).
    pub fn heatmap_file(slices: &[(i64, Vec<E>)]) -> Vec<u8> {
        let mut raw = Vec::new();
        let n = slices.len();
        for i in 0..n {
            raw.extend_from_slice(&(if i == 0 { n as i32 } else { 0 }).to_le_bytes());
            raw.extend_from_slice(&[0u8; 12]);
        }
        for (ts, ents) in slices {
            let ms = ts * 1000;
            raw.extend_from_slice(&MARKER.to_le_bytes());
            raw.extend_from_slice(&((ms >> 32) as i32).to_le_bytes());
            raw.extend_from_slice(&((ms & 0xFFFF_FFFF) as u32).to_le_bytes());
            raw.extend_from_slice(&10000i16.to_le_bytes());
            raw.extend_from_slice(&0i16.to_le_bytes());
            for e in ents {
                match e {
                    E::Pos(addr, lat, lon, alt, gs) => {
                        raw.extend_from_slice(&(*addr as i32).to_le_bytes());
                        raw.extend_from_slice(&((lat * 1e6).round() as i32).to_le_bytes());
                        raw.extend_from_slice(&((lon * 1e6).round() as i32).to_le_bytes());
                        raw.extend_from_slice(&alt.to_le_bytes());
                        raw.extend_from_slice(&gs.to_le_bytes());
                    }
                    E::Cs(addr, sq, cs) => {
                        raw.extend_from_slice(&(*addr as i32).to_le_bytes());
                        raw.extend_from_slice(&((1i32 << 30) | *sq as i32).to_le_bytes());
                        let mut c = [b' '; 8];
                        c[..cs.len()].copy_from_slice(cs.as_bytes());
                        raw.extend_from_slice(&c);
                    }
                }
            }
        }
        let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
        gz.write_all(&raw).unwrap();
        gz.finish().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::{testutil::*, *};
    use flate2::read::GzDecoder;

    #[test]
    fn parses_markers_callsigns_and_negative_coordinates() {
        let gz = heatmap_file(&[(1000, vec![E::Cs(0xabc123, 1200, "UAL12"), E::Pos(0xabc123, -33.5, -70.25, 1000, 2500)]), (1010, vec![E::Pos(0x1000001, 10.0, 20.0, -123, -1)])]);
        let mut out = vec![];
        parse(GzDecoder::new(&gz[..]), |r| { out.push(r); true }).unwrap();
        assert_eq!(out[0], Rec::Slice { ts_ms: 1_000_000 });
        assert_eq!(out[1], Rec::Callsign { addr: 0xabc123, squawk: 1200, callsign: "UAL12".into() });
        // a negative latitude must not be mistaken for a callsign record
        assert_eq!(out[2], Rec::Pos { addr: 0xabc123, lat: -33_500_000, lon: -70_250_000, alt: 1000, gs: 2500 });
        assert_eq!(out[3], Rec::Slice { ts_ms: 1_010_000 });
        assert!(matches!(out[4], Rec::Pos { alt: -123, .. }));
        assert_eq!(hex_string(0x1000001), "~000001");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[0u8; 64][..], |_| true).is_err());
    }
}
