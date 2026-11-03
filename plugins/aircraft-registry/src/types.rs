//! A short built-in list of common ICAO aircraft type designators (designator, name, class).
//! Not a mirror of the full ICAO 8643 list; anything else is answered from the registry record and the live feed.

const TYPES: &[(&str, &str, &str)] = &[
    ("A20N", "Airbus A320neo", "Jet airliner"), ("A21N", "Airbus A321neo", "Jet airliner"), ("A319", "Airbus A319", "Jet airliner"),
    ("A320", "Airbus A320", "Jet airliner"), ("A321", "Airbus A321", "Jet airliner"), ("A332", "Airbus A330-200", "Jet airliner"),
    ("A333", "Airbus A330-300", "Jet airliner"), ("A339", "Airbus A330-900", "Jet airliner"), ("A359", "Airbus A350-900", "Jet airliner"),
    ("A35K", "Airbus A350-1000", "Jet airliner"), ("A388", "Airbus A380-800", "Jet airliner"), ("A306", "Airbus A300-600", "Jet airliner"),
    ("A310", "Airbus A310", "Jet airliner"), ("A343", "Airbus A340-300", "Jet airliner"), ("A346", "Airbus A340-600", "Jet airliner"),
    ("B712", "Boeing 717-200", "Jet airliner"), ("B722", "Boeing 727-200", "Jet airliner"), ("B732", "Boeing 737-200", "Jet airliner"),
    ("B733", "Boeing 737-300", "Jet airliner"), ("B734", "Boeing 737-400", "Jet airliner"), ("B735", "Boeing 737-500", "Jet airliner"),
    ("B736", "Boeing 737-600", "Jet airliner"), ("B737", "Boeing 737-700", "Jet airliner"), ("B738", "Boeing 737-800", "Jet airliner"),
    ("B739", "Boeing 737-900", "Jet airliner"), ("B37M", "Boeing 737 MAX 7", "Jet airliner"), ("B38M", "Boeing 737 MAX 8", "Jet airliner"),
    ("B39M", "Boeing 737 MAX 9", "Jet airliner"), ("B3XM", "Boeing 737 MAX 10", "Jet airliner"), ("B744", "Boeing 747-400", "Jet airliner"),
    ("B748", "Boeing 747-8", "Jet airliner"), ("B752", "Boeing 757-200", "Jet airliner"), ("B753", "Boeing 757-300", "Jet airliner"),
    ("B762", "Boeing 767-200", "Jet airliner"), ("B763", "Boeing 767-300", "Jet airliner"), ("B764", "Boeing 767-400", "Jet airliner"),
    ("B772", "Boeing 777-200", "Jet airliner"), ("B77L", "Boeing 777-200LR", "Jet airliner"), ("B77W", "Boeing 777-300ER", "Jet airliner"),
    ("B778", "Boeing 777-8", "Jet airliner"), ("B779", "Boeing 777-9", "Jet airliner"), ("B788", "Boeing 787-8", "Jet airliner"),
    ("B789", "Boeing 787-9", "Jet airliner"), ("B78X", "Boeing 787-10", "Jet airliner"), ("BCS1", "Airbus A220-100", "Jet airliner"),
    ("BCS3", "Airbus A220-300", "Jet airliner"), ("E170", "Embraer 170", "Regional jet"), ("E75L", "Embraer 175 (long wing)", "Regional jet"),
    ("E75S", "Embraer 175 (short wing)", "Regional jet"), ("E190", "Embraer 190", "Regional jet"), ("E195", "Embraer 195", "Regional jet"),
    ("E290", "Embraer E190-E2", "Regional jet"), ("E295", "Embraer E195-E2", "Regional jet"), ("CRJ2", "Bombardier CRJ-200", "Regional jet"),
    ("CRJ7", "Bombardier CRJ-700", "Regional jet"), ("CRJ9", "Bombardier CRJ-900", "Regional jet"), ("CRJX", "Bombardier CRJ-1000", "Regional jet"),
    ("AT72", "ATR 72", "Turboprop airliner"), ("AT76", "ATR 72-600", "Turboprop airliner"), ("AT45", "ATR 42-500", "Turboprop airliner"),
    ("DH8D", "De Havilland Dash 8 Q400", "Turboprop airliner"), ("DH8C", "De Havilland Dash 8-300", "Turboprop airliner"),
    ("SF34", "Saab 340", "Turboprop airliner"), ("MD11", "McDonnell Douglas MD-11", "Jet airliner"), ("MD82", "McDonnell Douglas MD-82", "Jet airliner"),
    ("MD88", "McDonnell Douglas MD-88", "Jet airliner"), ("DC10", "McDonnell Douglas DC-10", "Jet airliner"), ("C172", "Cessna 172 Skyhawk", "Light piston"),
    ("C182", "Cessna 182 Skylane", "Light piston"), ("C208", "Cessna 208 Caravan", "Turboprop"), ("C25A", "Cessna Citation CJ2", "Business jet"),
    ("C25B", "Cessna Citation CJ3", "Business jet"), ("C510", "Cessna Citation Mustang", "Business jet"), ("C525", "Cessna CitationJet", "Business jet"),
    ("C550", "Cessna Citation II", "Business jet"), ("C56X", "Cessna Citation Excel", "Business jet"), ("C680", "Cessna Citation Sovereign", "Business jet"),
    ("C750", "Cessna Citation X", "Business jet"), ("PA28", "Piper PA-28 Cherokee", "Light piston"), ("PA46", "Piper PA-46 Malibu", "Light piston"),
    ("SR20", "Cirrus SR20", "Light piston"), ("SR22", "Cirrus SR22", "Light piston"), ("BE20", "Beechcraft King Air 200", "Turboprop"),
    ("BE9L", "Beechcraft King Air 90", "Turboprop"), ("BE58", "Beechcraft Baron 58", "Light piston"), ("PC12", "Pilatus PC-12", "Turboprop"),
    ("TBM9", "Daher TBM 900 series", "Turboprop"), ("GLF4", "Gulfstream IV", "Business jet"), ("GLF5", "Gulfstream V", "Business jet"),
    ("GLF6", "Gulfstream G650", "Business jet"), ("GL5T", "Bombardier Global 5000", "Business jet"), ("GLEX", "Bombardier Global Express", "Business jet"),
    ("CL35", "Bombardier Challenger 350", "Business jet"), ("CL60", "Bombardier Challenger 600 series", "Business jet"), ("FA7X", "Dassault Falcon 7X", "Business jet"),
    ("FA50", "Dassault Falcon 50", "Business jet"), ("LJ45", "Learjet 45", "Business jet"), ("HDJT", "Honda HA-420 HondaJet", "Business jet"),
    ("E55P", "Embraer Phenom 300", "Business jet"), ("R44", "Robinson R44", "Helicopter"), ("R22", "Robinson R22", "Helicopter"),
    ("EC35", "Airbus Helicopters EC135", "Helicopter"), ("B06", "Bell 206 JetRanger", "Helicopter"), ("S76", "Sikorsky S-76", "Helicopter"),
    ("H60", "Sikorsky UH-60 Black Hawk", "Military helicopter"), ("C130", "Lockheed C-130 Hercules", "Military transport"), ("C17", "Boeing C-17 Globemaster III", "Military transport"),
    ("K35R", "Boeing KC-135R Stratotanker", "Military tanker"), ("A400", "Airbus A400M Atlas", "Military transport"), ("P8", "Boeing P-8 Poseidon", "Military patrol"),
    ("E3TF", "Boeing E-3 Sentry (AWACS)", "Military AEW"),
];

/// (designator, name, class) for a designator, case-insensitive.
pub fn lookup(code: &str) -> Option<(&'static str, &'static str, &'static str)> {
    TYPES.iter().find(|t| t.0.eq_ignore_ascii_case(code)).copied()
}

#[cfg(test)]
mod tests {
    #[test]
    fn finds_and_is_unique() {
        assert_eq!(super::lookup("b738").unwrap().1, "Boeing 737-800");
        assert!(super::lookup("QQQQ").is_none());
        let mut seen = std::collections::HashSet::new();
        assert!(super::TYPES.iter().all(|t| seen.insert(t.0)), "duplicate designator");
    }
}
