//! Rendering a pairing payload as a QR code.
//!
//! Uses the `qrcode` crate rather than a hand-rolled encoder. A QR encoder is
//! several hundred lines of bit-level detail — Reed-Solomon over GF(256), block
//! interleaving, eight mask patterns scored against four penalty rules, version
//! and format information — and every one of those is a chance to emit a symbol
//! that looks plausible and does not scan.
//!
//! The crate is built with only the `svg` feature, so it pulls in no image
//! codecs. SVG is also the better output here: it scales without resampling and
//! prints cleanly, where a bitmap needs a scale factor guessed for a screen.
//!
//! The payload is built by `crate::cloud::qr_payload` over the shared
//! protocol encoder, so the app parses exactly one shape.

use anyhow::{Context, Result, ensure};
use qrcode::QrCode;

/// Error correction level M, about 15% recovery.
///
/// Enough redundancy to survive a reflection or a smudge on a screen without
/// making the code so dense it stops resolving at arm's length. Level Q would
/// tolerate more damage but produce a denser symbol for the same payload, which
/// matters because the payload carries a 64-character token.
const ECC: qrcode::EcLevel = qrcode::EcLevel::M;

/// Render a pairing payload as an SVG string.
///
/// The result is a standalone document with a quiet zone, which is what the
/// standard requires for a scanner to lock onto the symbol.
pub fn to_svg(payload: &str) -> Result<String> {
    // The encoder would happily produce a symbol for an empty payload, which a
    // scanner reads as a stray character rather than as a failure. A pairing
    // payload always carries a device id and a token, so an empty one is a bug
    // upstream and should be reported as such.
    ensure!(!payload.is_empty(), "refusing to encode an empty payload");

    let code = QrCode::with_error_correction_level(payload.as_bytes(), ECC)
        .with_context(|| format!("the payload cannot be encoded as a QR symbol: {payload:.40}"))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(512, 512)
        .quiet_zone(true)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    Ok(svg)
}

/// Write the SVG beside the credentials.
pub fn write_svg(path: &std::path::Path, payload: &str) -> Result<()> {
    let svg = to_svg(payload)?;
    ensure!(
        !svg.is_empty(),
        "the QR renderer produced an empty document"
    );
    std::fs::write(path, svg)
        .with_context(|| format!("writing the QR image to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic pairing payload: 139 bytes, which is what the pairing URL
    /// actually comes to with a 32-byte token and a 16-byte device id.
    fn sample() -> String {
        crate::cloud::qr_payload(
            "6167672d303030316167672d30303031",
            &"0123456789abcdef".repeat(4),
            "0202020202020202",
        )
        .unwrap()
    }

    #[test]
    fn a_realistic_payload_renders() {
        let svg = to_svg(&sample()).expect("a pairing payload must encode");
        assert!(svg.contains("<svg "), "not an svg document: {svg:.60}");
        assert!(svg.trim_end().ends_with("</svg>"));
        assert!(svg.contains("<path"), "the symbol is drawn as paths");
        assert!(svg.contains("#000000"), "dark modules are black");
        assert!(
            svg.contains("#ffffff"),
            "the background is white, for contrast"
        );
    }

    #[test]
    fn the_symbol_is_large_enough_to_scan() {
        // The renderer honours `min_dimensions`, so the symbol is at least 512
        // across. A denser payload grows it rather than shrinking the modules.
        let svg = to_svg(&sample()).unwrap();
        let width: u32 = svg
            .split("width=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .and_then(|value| value.parse().ok())
            .expect("the svg declares a width");
        assert!(width >= 512, "a pairing symbol must not be tiny: {width}");
    }

    #[test]
    fn an_empty_payload_is_refused() {
        // An empty payload would produce a symbol encoding nothing, which a
        // scanner reads as a stray character rather than as a failure.
        assert!(to_svg("").is_err());
    }

    #[test]
    fn the_svg_is_a_self_contained_document() {
        let svg = to_svg(&sample()).unwrap();
        // The only URL is the SVG namespace, which is an identifier rather than
        // a fetch. Nothing may be loaded from disk or network.
        assert!(!svg.contains("<script"), "no scripts expected");
        assert!(!svg.contains("<image"), "no embedded images expected");
        let urls: Vec<&str> = svg
            .match_indices("http")
            .map(|(index, _)| &svg[index..(index + 40).min(svg.len())])
            .collect();
        for url in urls {
            assert!(
                url.starts_with("http://www.w3.org/2000/svg"),
                "unexpected external reference: {url}"
            );
        }
    }
}
