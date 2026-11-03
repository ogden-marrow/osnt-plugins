//! Audio decoding (WAV, MP3, AAC/M4A, OGG Vorbis, FLAC) to mono f32 via pure-Rust symphonia.

use std::io::Cursor;

use symphonia::core::{
    audio::SampleBuffer, codecs::DecoderOptions, errors::Error as SymErr, formats::FormatOptions, io::MediaSourceStream,
    meta::MetadataOptions, probe::Hint,
};

pub struct Audio {
    pub samples: Vec<f32>,
    pub sample_rate: u32,
    pub channels: usize,
}

/// Decode `data` to a mono signal. Rejects clips longer than `max_seconds` (the decoder stops early, so a huge
/// compressed file cannot blow up memory).
pub fn decode(data: Vec<u8>, max_seconds: f64) -> Result<Audio, String> {
    let mss = MediaSourceStream::new(Box::new(Cursor::new(data)), Default::default());
    let probed = symphonia::default::get_probe()
        .format(&Hint::new(), mss, &FormatOptions::default(), &MetadataOptions::default())
        .map_err(|_| "unrecognised audio format (supported: WAV, MP3, AAC/M4A, OGG, FLAC)".to_string())?;
    let mut format = probed.format;
    let track = format
        .tracks()
        .iter()
        .find(|t| t.codec_params.sample_rate.is_some())
        .ok_or("no decodable audio track")?
        .clone();
    let mut decoder = symphonia::default::get_codecs()
        .make(&track.codec_params, &DecoderOptions::default())
        .map_err(|e| format!("unsupported codec: {e}"))?;
    let sample_rate = track.codec_params.sample_rate.ok_or("unknown sample rate")?;
    if sample_rate < 4000 {
        return Err("sample rate below 4 kHz is not useful for this analysis".into());
    }
    let max_samples = (max_seconds * sample_rate as f64) as usize;
    let mut out: Vec<f32> = Vec::new();
    let mut channels = 1usize;
    loop {
        let packet = match format.next_packet() {
            Ok(p) => p,
            Err(SymErr::IoError(_)) | Err(SymErr::ResetRequired) => break,
            Err(e) => return Err(format!("decode error: {e}")),
        };
        if packet.track_id() != track.id {
            continue;
        }
        let decoded = match decoder.decode(&packet) {
            Ok(d) => d,
            Err(SymErr::DecodeError(_)) => continue, // skip a corrupt frame
            Err(e) => return Err(format!("decode error: {e}")),
        };
        let spec = *decoded.spec();
        channels = spec.channels.count().max(1);
        let mut buf = SampleBuffer::<f32>::new(decoded.capacity() as u64, spec);
        buf.copy_interleaved_ref(decoded);
        for frame in buf.samples().chunks(channels) {
            out.push(frame.iter().sum::<f32>() / channels as f32);
        }
        if out.len() > max_samples {
            return Err(format!("clip is longer than {max_seconds:.0} s; trim it around the pass and retry"));
        }
    }
    if out.len() < sample_rate as usize / 2 {
        return Err("clip is too short (under 0.5 s)".into());
    }
    Ok(Audio { samples: out, sample_rate, channels })
}
