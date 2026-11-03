//! Sun position and rise/set from the NOAA solar calculator equations (Jean Meeus, "Astronomical Algorithms").
//! Accuracy is about 0.01 degrees in position and a minute in rise/set for dates within a few centuries of 2000.
//! Everything is pure maths: no data files and no network.

use std::f64::consts::PI;

fn rad(d: f64) -> f64 {
    d * PI / 180.0
}
fn deg(r: f64) -> f64 {
    r * 180.0 / PI
}

/// Julian day for seconds since the Unix epoch (UTC).
pub fn julian_day(unix: f64) -> f64 {
    unix / 86400.0 + 2440587.5
}

/// Intermediate values that depend only on the instant.
#[derive(Debug, Clone, Copy)]
pub struct Astro {
    /// Declination of the sun in degrees.
    pub declination: f64,
    /// Equation of time in minutes (apparent minus mean solar time).
    pub eq_time: f64,
}

pub fn astro(unix: f64) -> Astro {
    let t = (julian_day(unix) - 2451545.0) / 36525.0;
    let l0 = (280.46646 + t * (36000.76983 + t * 0.0003032)).rem_euclid(360.0);
    let m = 357.52911 + t * (35999.05029 - 0.0001537 * t);
    let e = 0.016708634 - t * (0.000042037 + 0.0000001267 * t);
    let (mr, l0r) = (rad(m), rad(l0));
    let c = mr.sin() * (1.914602 - t * (0.004817 + 0.000014 * t)) + (2.0 * mr).sin() * (0.019993 - 0.000101 * t) + (3.0 * mr).sin() * 0.000289;
    let true_long = l0 + c;
    let omega = 125.04 - 1934.136 * t;
    let app_long = true_long - 0.00569 - 0.00478 * rad(omega).sin();
    let mean_obliq = 23.0 + (26.0 + (21.448 - t * (46.815 + t * (0.00059 - t * 0.001813))) / 60.0) / 60.0;
    let obliq = mean_obliq + 0.00256 * rad(omega).cos();
    let declination = deg((rad(obliq).sin() * rad(app_long).sin()).asin());
    let y = (rad(obliq) / 2.0).tan().powi(2);
    let eq_time = 4.0
        * deg(y * (2.0 * l0r).sin() - 2.0 * e * mr.sin() + 4.0 * e * y * mr.sin() * (2.0 * l0r).cos() - 0.5 * y * y * (4.0 * l0r).sin() - 1.25 * e * e * (2.0 * mr).sin());
    Astro { declination, eq_time }
}

/// Atmospheric refraction in degrees for a geometric elevation in degrees (NOAA approximation, standard atmosphere).
pub fn refraction(elev: f64) -> f64 {
    if elev > 85.0 {
        return 0.0;
    }
    let te = rad(elev).tan();
    let arcsec = if elev > 5.0 {
        58.1 / te - 0.07 / te.powi(3) + 0.000086 / te.powi(5)
    } else if elev > -0.575 {
        1735.0 + elev * (-518.2 + elev * (103.4 + elev * (-12.79 + elev * 0.711)))
    } else {
        -20.772 / te
    };
    arcsec / 3600.0
}

#[derive(Debug, Clone, Copy)]
pub struct SunPos {
    /// Degrees clockwise from true north, 0..360.
    pub azimuth: f64,
    /// Apparent elevation above the horizon in degrees (with refraction).
    pub altitude: f64,
    /// Geometric elevation in degrees (no refraction).
    pub geometric: f64,
    pub declination: f64,
    pub eq_time: f64,
}

/// Sun position for a latitude and east-positive longitude (degrees) at `unix` seconds (UTC).
pub fn position(lat: f64, lon: f64, unix: f64) -> SunPos {
    let a = astro(unix);
    let utc_min = unix.rem_euclid(86400.0) / 60.0;
    let tst = (utc_min + a.eq_time + 4.0 * lon).rem_euclid(1440.0);
    let mut ha = tst / 4.0 - 180.0;
    if ha < -180.0 {
        ha += 360.0;
    }
    let (latr, decr, har) = (rad(lat), rad(a.declination), rad(ha));
    let cos_zen = (latr.sin() * decr.sin() + latr.cos() * decr.cos() * har.cos()).clamp(-1.0, 1.0);
    let zen = cos_zen.acos();
    let geometric = 90.0 - deg(zen);
    let denom = latr.cos() * zen.sin();
    let az_base = if denom.abs() < 1e-12 { 180.0 } else { deg((((latr.sin() * cos_zen) - decr.sin()) / denom).clamp(-1.0, 1.0).acos()) };
    let azimuth = if ha > 0.0 { (az_base + 180.0).rem_euclid(360.0) } else { (540.0 - az_base).rem_euclid(360.0) };
    SunPos { azimuth, altitude: geometric + refraction(geometric), geometric, declination: a.declination, eq_time: a.eq_time }
}

/// Geometric elevation that gives the apparent elevation `apparent` (inverse of `refraction`, by fixed-point iteration).
pub fn geometric_from_apparent(apparent: f64) -> f64 {
    let mut g = apparent;
    for _ in 0..8 {
        g = apparent - refraction(g);
    }
    g
}

/// Sub-solar point (latitude, east longitude in -180..180) at `unix`.
pub fn subsolar(unix: f64) -> (f64, f64) {
    let a = astro(unix);
    let utc_min = unix.rem_euclid(86400.0) / 60.0;
    let mut lon = (720.0 - utc_min - a.eq_time) / 4.0;
    lon = (lon + 180.0).rem_euclid(360.0) - 180.0;
    (a.declination, lon)
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    At(f64),
    /// Sun stays above the horizon all day.
    AlwaysUp,
    /// Sun stays below the horizon all day.
    AlwaysDown,
}

#[derive(Debug, Clone)]
pub struct DayTimes {
    /// Unix seconds of the local solar noon.
    pub noon: f64,
    pub sunrise: Event,
    pub sunset: Event,
    /// Maximum elevation (geometric) at solar noon.
    pub noon_elevation: f64,
    /// Day length in hours (0 or 24 at the poles).
    pub day_hours: f64,
}

/// Rise, set and noon for the solar day whose UTC calendar date starts at `day_start` (unix seconds at 00:00 UTC).
/// Times are for the solar day at this longitude, so they can fall on the neighbouring UTC date far from Greenwich.
pub fn day_times(lat: f64, lon: f64, day_start: f64) -> DayTimes {
    let noon_guess = day_start + (720.0 - 4.0 * lon) * 60.0;
    let noon = noon_guess - astro(noon_guess).eq_time * 60.0;
    let noon = noon_guess - astro(noon).eq_time * 60.0;
    let noon_astro = astro(noon);
    let noon_elevation = 90.0 - (lat - noon_astro.declination).abs();
    // Hour angle (degrees from solar noon) at which the sun's centre is 0.833 degrees below the horizon at instant `t`:
    // Ok(angle), or Err(true) when the sun never sets and Err(false) when it never rises.
    let ha_for = |t: f64| -> Result<f64, bool> {
        let a = astro(t);
        let (latr, decr) = (rad(lat), rad(a.declination));
        let c = rad(90.833).cos() / (latr.cos() * decr.cos()) - latr.tan() * decr.tan();
        if c.is_nan() || c > 1.0 {
            Err(false)
        } else if c < -1.0 {
            Err(true)
        } else {
            Ok(deg(c.acos()))
        }
    };
    // Iterate because the declination changes a little between noon and the event.
    let solve = |sign: f64| -> Event {
        let mut t = noon + sign * 6.0 * 3600.0;
        for _ in 0..4 {
            match ha_for(t) {
                Ok(ha) => t = noon + sign * ha * 4.0 * 60.0,
                Err(up) => return if up { Event::AlwaysUp } else { Event::AlwaysDown },
            }
        }
        Event::At(t)
    };
    let (sunrise, sunset) = (solve(-1.0), solve(1.0));
    let day_hours = match (&sunrise, &sunset) {
        (Event::At(a), Event::At(b)) => (b - a) / 3600.0,
        (Event::AlwaysUp, _) | (_, Event::AlwaysUp) => 24.0,
        _ => 0.0,
    };
    DayTimes { noon, sunrise, sunset, noon_elevation, day_hours }
}

/// Shadow length for an object of `height` at apparent sun elevation `alt` degrees; None when the sun is at or below the horizon.
pub fn shadow_length(height: f64, alt: f64) -> Option<f64> {
    (alt > 0.0).then(|| height / rad(alt).tan())
}

/// Destination on a sphere: start (lat, lon), bearing and angular distance in degrees.
pub fn destination(lat: f64, lon: f64, bearing: f64, ang: f64) -> (f64, f64) {
    let (p1, l1, b, d) = (rad(lat), rad(lon), rad(bearing), rad(ang));
    let p2 = (p1.sin() * d.cos() + p1.cos() * d.sin() * b.cos()).clamp(-1.0, 1.0).asin();
    let l2 = l1 + (b.sin() * d.sin() * p1.cos()).atan2(d.cos() - p1.sin() * p2.sin());
    (deg(p2), (deg(l2) + 540.0).rem_euclid(360.0) - 180.0)
}

/// The set of places where the sun has apparent elevation `alt` at one instant is a circle around the sub-solar point
/// with angular radius 90 - geometric elevation. Returns its points (lat, lon) for `n` bearings.
pub fn equal_altitude_circle(unix: f64, alt: f64, n: usize) -> Vec<(f64, f64)> {
    let (slat, slon) = subsolar(unix);
    let radius = 90.0 - geometric_from_apparent(alt);
    (0..n).map(|i| destination(slat, slon, 360.0 * i as f64 / n as f64, radius)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeparse::parse_time;

    fn t(s: &str) -> f64 {
        parse_time(s).unwrap()
    }

    #[test]
    fn meeus_example_25a_declination() {
        // Meeus, Astronomical Algorithms, example 25.a: 1992-10-13 00:00 TD, apparent declination -7.78507 degrees.
        // TD is about 59 s ahead of UT in 1992, which moves the declination by about 0.005 degrees.
        let a = astro(t("1992-10-13T00:00:00Z") - 59.0);
        assert!((a.declination - -7.78507).abs() < 0.01, "{}", a.declination);
        // Equation of time for that date is about +13.7 minutes.
        assert!((a.eq_time - 13.7).abs() < 0.2, "{}", a.eq_time);
    }

    #[test]
    fn solstice_and_equinox_declination() {
        assert!(astro(t("2024-03-20T03:06:00Z")).declination.abs() < 0.02);
        assert!((astro(t("2024-06-20T20:51:00Z")).declination - 23.436).abs() < 0.02);
        assert!((astro(t("2024-12-21T09:21:00Z")).declination + 23.436).abs() < 0.02);
    }

    #[test]
    fn noon_on_the_equator_at_the_equinox_is_overhead() {
        let p = position(0.0, 0.0, t("2024-03-20T12:07:00Z"));
        assert!(p.geometric > 89.0, "{p:?}");
    }

    #[test]
    fn known_noon_altitude_and_azimuth() {
        // London on the June solstice: solar noon at ~12:01 UTC, elevation 90 - (51.5 - 23.44) = 61.9, due south.
        let p = position(51.5074, -0.1278, t("2024-06-20T11:59:00Z"));
        assert!((p.geometric - 61.93).abs() < 0.1, "{p:?}");
        assert!((p.azimuth - 180.0).abs() < 2.0, "{p:?}");
        // Morning: sun in the east-north-east, afternoon: west-north-west.
        assert!(position(51.5074, -0.1278, t("2024-06-20T06:00:00Z")).azimuth < 90.0);
        assert!(position(51.5074, -0.1278, t("2024-06-20T19:00:00Z")).azimuth > 270.0);
    }

    #[test]
    fn sunrise_sunset_match_published_times() {
        // London, 2024-06-21: sunrise 03:43 UTC (04:43 BST), sunset 20:21 UTC.
        let d = day_times(51.5074, -0.1278, t("2024-06-21T00:00:00Z"));
        let (Event::At(r), Event::At(s)) = (d.sunrise.clone(), d.sunset.clone()) else { panic!("{d:?}") };
        assert!((r - t("2024-06-21T03:43:00Z")).abs() < 150.0, "sunrise off by {} s", r - t("2024-06-21T03:43:00Z"));
        assert!((s - t("2024-06-21T20:21:00Z")).abs() < 150.0, "sunset off by {} s", s - t("2024-06-21T20:21:00Z"));
        assert!((d.day_hours - 16.63).abs() < 0.1, "{}", d.day_hours);
        // New York, 2024-12-21: sunrise 07:16 EST (12:16 UTC), sunset 16:32 EST (21:32 UTC).
        let d = day_times(40.7128, -74.006, t("2024-12-21T00:00:00Z"));
        let (Event::At(r), Event::At(s)) = (d.sunrise, d.sunset) else { panic!() };
        assert!((r - t("2024-12-21T12:16:00Z")).abs() < 150.0, "{}", r - t("2024-12-21T12:16:00Z"));
        assert!((s - t("2024-12-21T21:32:00Z")).abs() < 150.0, "{}", s - t("2024-12-21T21:32:00Z"));
    }

    #[test]
    fn polar_day_and_night() {
        let d = day_times(78.22, 15.65, t("2024-06-21T00:00:00Z"));
        assert_eq!(d.sunrise, Event::AlwaysUp);
        assert_eq!(d.day_hours, 24.0);
        let d = day_times(78.22, 15.65, t("2024-12-21T00:00:00Z"));
        assert_eq!(d.sunset, Event::AlwaysDown);
        assert_eq!(d.day_hours, 0.0);
    }

    #[test]
    fn sunrise_for_far_east_longitudes_stays_on_the_solar_day() {
        // Auckland 2024-06-21 (local solar day): sunrise ~07:29 NZST = 19:29 UTC the day before.
        let d = day_times(-36.85, 174.76, t("2024-06-21T00:00:00Z"));
        let Event::At(r) = d.sunrise else { panic!() };
        assert!((r - t("2024-06-20T19:29:00Z")).abs() < 360.0, "{}", r - t("2024-06-20T19:29:00Z"));
    }

    #[test]
    fn refraction_inverse() {
        for a in [0.0, 1.0, 5.0, 30.0] {
            let g = geometric_from_apparent(a);
            assert!((g + refraction(g) - a).abs() < 1e-6, "{a}");
        }
        assert!((refraction(0.0) - 0.4833).abs() < 0.05);
    }

    #[test]
    fn subsolar_point_has_overhead_sun() {
        let when = t("2024-09-01T09:30:00Z");
        let (lat, lon) = subsolar(when);
        let p = position(lat, lon, when);
        assert!(p.geometric > 89.9, "{p:?}");
    }

    #[test]
    fn circle_points_have_the_requested_altitude() {
        let when = t("2024-05-02T14:11:00Z");
        for alt in [10.0, 35.0, 62.5] {
            for (lat, lon) in equal_altitude_circle(when, alt, 24) {
                let p = position(lat, lon, when);
                assert!((p.altitude - alt).abs() < 0.01, "{alt}: {p:?}");
            }
        }
    }

    #[test]
    fn shadow_geometry() {
        assert!((shadow_length(10.0, 45.0).unwrap() - 10.0).abs() < 1e-9);
        assert!(shadow_length(10.0, 0.0).is_none());
        assert!(shadow_length(10.0, -5.0).is_none());
        assert!((shadow_length(1.0, 30.0).unwrap() - 1.7320508).abs() < 1e-6);
    }

    #[test]
    fn destination_goes_the_right_way() {
        let (la, lo) = destination(0.0, 0.0, 90.0, 10.0);
        assert!(la.abs() < 1e-9 && (lo - 10.0).abs() < 1e-9);
        let (la, _) = destination(80.0, 0.0, 0.0, 20.0);
        assert!((la - 80.0).abs() < 10.1 && la < 90.0);
    }
}
