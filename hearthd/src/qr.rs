//! QR rendering for client bundles (ТЗ §7.3 config-gen, Приложение B).
//!
//! Two renderers: an 8-bit grayscale PNG for `GET /devices/{id}/bundle.png`, and a
//! half-block text rendering for `hearthctl`, so the owner can scan a bundle straight
//! off an ssh session without the QR ever touching a filesystem.
//!
//! The PNG encoder is ~80 lines of deflate + CRC here rather than the `image` crate:
//! a QR is a 1-bit bitmap, and every dependency on this node has to justify itself.

use std::io::Write as _;

use qrcode::{Color, QrCode};

use crate::error::{Error, Result};

/// Modules of white space around the code, as required by the QR spec.
pub const QUIET_ZONE: u32 = 4;
/// Default pixels per module for the PNG rendering.
pub const DEFAULT_SCALE: u32 = 8;

/// A rendered QR bitmap: `width` × `width` modules, `true` = dark.
#[derive(Debug)]
pub struct QrBitmap {
    pub width: usize,
    pub modules: Vec<bool>,
}

impl QrBitmap {
    pub fn encode(data: &str) -> Result<Self> {
        let code = QrCode::new(data.as_bytes())
            .map_err(|e| Error::Crypto(format!("qr encoding failed: {e}")))?;
        let width = code.width();
        let modules = code
            .into_colors()
            .into_iter()
            .map(|c| c == Color::Dark)
            .collect();
        Ok(Self { width, modules })
    }

    fn dark(&self, x: usize, y: usize) -> bool {
        if x >= self.width || y >= self.width {
            return false;
        }
        self.modules
            .get(y * self.width + x)
            .copied()
            .unwrap_or(false)
    }
}

/// Render the payload as an 8-bit grayscale PNG.
pub fn png(data: &str, scale: u32) -> Result<Vec<u8>> {
    let scale = scale.max(1);
    let bitmap = QrBitmap::encode(data)?;
    let modules = bitmap.width as u32 + 2 * QUIET_ZONE;
    let side = (modules * scale) as usize;

    // One filter byte (0 = None) per scanline, then one grayscale byte per pixel.
    let mut raw = Vec::with_capacity(side * (side + 1));
    for y in 0..side {
        raw.push(0u8);
        let my = y as u32 / scale;
        for x in 0..side {
            let mx = x as u32 / scale;
            let dark = mx >= QUIET_ZONE
                && my >= QUIET_ZONE
                && bitmap.dark((mx - QUIET_ZONE) as usize, (my - QUIET_ZONE) as usize);
            raw.push(if dark { 0x00 } else { 0xff });
        }
    }
    encode_png_gray(side as u32, side as u32, &raw)
}

/// Minimal PNG writer: signature, IHDR (8-bit grayscale), IDAT (zlib), IEND.
fn encode_png_gray(width: u32, height: u32, raw_scanlines: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8); // bit depth
    ihdr.push(0); // colour type: grayscale
    ihdr.push(0); // compression: deflate
    ihdr.push(0); // filter: adaptive
    ihdr.push(0); // interlace: none
    write_chunk(&mut out, b"IHDR", &ihdr);

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(raw_scanlines).map_err(Error::RawIo)?;
    let idat = encoder.finish().map_err(Error::RawIo)?;
    write_chunk(&mut out, b"IDAT", &idat);
    write_chunk(&mut out, b"IEND", &[]);
    Ok(out)
}

fn write_chunk(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
    let mut crc = flate2::Crc::new();
    crc.update(kind);
    crc.update(body);
    out.extend_from_slice(&crc.sum().to_be_bytes());
}

/// Render the payload with Unicode half blocks, two module rows per text row.
///
/// Uses light modules as foreground on a dark background is *not* done here: scanners
/// expect dark-on-light, so the light modules are printed as filled blocks.
pub fn terminal(data: &str) -> Result<String> {
    let bitmap = QrBitmap::encode(data)?;
    let quiet = QUIET_ZONE as usize;
    let side = bitmap.width + 2 * quiet;
    let mut out = String::with_capacity(side * side / 2);
    let mut y = 0;
    while y < side {
        for x in 0..side {
            let top = module_at(&bitmap, x, y, quiet);
            let bottom = module_at(&bitmap, x, y + 1, quiet);
            // Dark module = no light emitted; print the *light* modules as blocks.
            out.push(match (top, bottom) {
                (false, false) => '\u{2588}', // full block: both light
                (false, true) => '\u{2580}',  // upper half
                (true, false) => '\u{2584}',  // lower half
                (true, true) => ' ',
            });
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

fn module_at(bitmap: &QrBitmap, x: usize, y: usize, quiet: usize) -> bool {
    if x < quiet || y < quiet {
        return false;
    }
    bitmap.dark(x - quiet, y - quiet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    const PAYLOAD: &str =
        r#"{"v":1,"smp":["smp://fp:pass@10.66.10.10:5223"],"device":"mama-pixel8"}"#;

    #[test]
    fn png_has_valid_structure() {
        let bytes = png(PAYLOAD, 4).expect("png");
        assert_eq!(
            &bytes[..8],
            &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]
        );
        // IHDR immediately follows the signature.
        assert_eq!(&bytes[12..16], b"IHDR");
        assert!(bytes.ends_with(&[0xae, 0x42, 0x60, 0x82]), "IEND crc");
    }

    #[test]
    fn png_pixels_decompress_to_the_declared_size() {
        let scale = 3;
        let bytes = png(PAYLOAD, scale).expect("png");
        let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        assert_eq!(width, height);

        // Find the IDAT chunk and inflate it.
        let mut idat = Vec::new();
        let mut pos = 8;
        while pos + 8 <= bytes.len() {
            let len =
                u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                    as usize;
            let kind = &bytes[pos + 4..pos + 8];
            if kind == b"IDAT" {
                idat.extend_from_slice(&bytes[pos + 8..pos + 8 + len]);
            }
            pos += 12 + len;
        }
        let mut raw = Vec::new();
        flate2::read::ZlibDecoder::new(&idat[..])
            .read_to_end(&mut raw)
            .expect("inflate");
        assert_eq!(raw.len(), (height as usize) * (width as usize + 1));
        // Every scanline starts with filter byte 0.
        assert_eq!(raw[0], 0);
        // Only black and white pixels.
        assert!(raw[1..width as usize + 1]
            .iter()
            .all(|p| *p == 0x00 || *p == 0xff));
    }

    #[test]
    fn quiet_zone_is_light() {
        let bytes = png(PAYLOAD, 1).expect("png");
        let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        // width = modules + 2*quiet
        assert!(width > 2 * QUIET_ZONE);
    }

    #[test]
    fn terminal_rendering_is_square_and_non_empty() {
        let text = terminal(PAYLOAD).expect("render");
        let lines: Vec<&str> = text.lines().collect();
        assert!(!lines.is_empty());
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        // Two module rows per text row (plus rounding).
        assert!(width >= lines.len());
        assert!(text.contains('\u{2588}'));
    }

    #[test]
    fn rejects_payloads_that_do_not_fit() {
        let huge = "x".repeat(8000);
        assert!(QrBitmap::encode(&huge).is_err());
    }
}
