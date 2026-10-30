//! Copying a UF2 image onto a mounted BOOTSEL volume.
//!
//! Validation is strict before anything is written to the mass-storage
//! volume: the volume only holds one file at a time and a half-written or
//! wrong-target image is a board that will not boot, discovered only after
//! a trip to the field.

use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

const BLOCK_SIZE: usize = 512;
const DATA_START: usize = 32;
const DATA_END: usize = 508;
const UF2_MAGIC_START0: u32 = 0x0A32_4655;
const UF2_MAGIC_START1: u32 = 0x9E5D_5157;
const UF2_MAGIC_END: u32 = 0x0AB1_6F30;
const UF2_FLAG_FAMILY_ID_PRESENT: u32 = 0x0000_2000;
const RP2040_FAMILY_ID: u32 = 0xE48B_FF56;
const MAX_UF2_SIZE: u64 = 64 * 1024 * 1024;

/// Validate a whole UF2 image, returning the block count.
pub fn validate_uf2_bytes(bytes: &[u8]) -> Result<usize> {
    validate_uf2(&mut Cursor::new(bytes))
}

/// Validate a UF2 read from a stream, leaving the reader's position
/// unspecified; callers seeking a copy must rewind first.
pub fn validate_uf2<R: Read + Seek>(reader: &mut R) -> Result<usize> {
    let length = reader.seek(SeekFrom::End(0)).context("measure UF2 file")?;
    ensure!(
        length > 0 && length % BLOCK_SIZE as u64 == 0,
        "UF2 length must be a nonzero multiple of 512 bytes"
    );
    ensure!(
        length <= MAX_UF2_SIZE,
        "UF2 file exceeds the 64 MiB safety limit"
    );
    let block_count = (length / BLOCK_SIZE as u64) as usize;
    ensure!(block_count <= u32::MAX as usize, "UF2 has too many blocks");
    reader.seek(SeekFrom::Start(0)).context("rewind UF2 file")?;

    let mut seen = vec![false; block_count];
    let mut block = [0u8; BLOCK_SIZE];
    let mut declared_total = None;
    for _ in 0..block_count {
        reader.read_exact(&mut block).context("read UF2 block")?;
        ensure!(
            read_u32(&block, 0) == UF2_MAGIC_START0,
            "invalid UF2 start magic 0"
        );
        ensure!(
            read_u32(&block, 4) == UF2_MAGIC_START1,
            "invalid UF2 start magic 1"
        );
        let flags = read_u32(&block, 8);
        ensure!(
            flags & UF2_FLAG_FAMILY_ID_PRESENT != 0,
            "UF2 block does not declare a target family"
        );
        ensure!(
            read_u32(&block, 28) == RP2040_FAMILY_ID,
            "UF2 block does not target RP2040"
        );
        ensure!(
            read_u32(&block, 508) == UF2_MAGIC_END,
            "invalid UF2 end magic"
        );

        let payload_size = read_u32(&block, 16) as usize;
        ensure!(
            (1..=DATA_END - DATA_START).contains(&payload_size),
            "invalid UF2 payload size {payload_size}"
        );
        let block_number = read_u32(&block, 20) as usize;
        let total_blocks = read_u32(&block, 24) as usize;
        ensure!(
            total_blocks == block_count,
            "UF2 total-block count does not match file length"
        );
        ensure!(
            block_number < total_blocks,
            "UF2 block number is out of range"
        );
        ensure!(
            !seen[block_number],
            "duplicate UF2 block number {block_number}"
        );
        seen[block_number] = true;
        match declared_total {
            Some(total) => ensure!(
                total == total_blocks,
                "UF2 blocks disagree on total-block count"
            ),
            None => declared_total = Some(total_blocks),
        }
    }
    ensure!(
        seen.iter().all(|present| *present),
        "UF2 is missing one or more blocks"
    );
    Ok(block_count)
}

/// Copy a validated UF2 onto a BOOTSEL mass-storage volume.
///
/// The mount must already look like a Pico in BOOTSEL mode (an
/// `INFO_UF2.TXT` at its root), and an existing image is never
/// overwritten: flashing twice is a mistake worth reporting, not
/// silently accepting.
pub fn flash_uf2(firmware: &Path, bootsel_mount: &Path) -> Result<PathBuf> {
    ensure!(
        firmware
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("uf2")),
        "firmware file must have a .uf2 extension"
    );
    ensure!(
        bootsel_mount.is_dir(),
        "BOOTSEL mount is not a directory: {}",
        bootsel_mount.display()
    );
    ensure!(
        bootsel_mount.join("INFO_UF2.TXT").is_file(),
        "{} does not look like a Pico BOOTSEL volume (INFO_UF2.TXT missing)",
        bootsel_mount.display()
    );

    let name = firmware
        .file_name()
        .context("firmware path has no filename")?;
    let destination = bootsel_mount.join(name);
    let mut source = File::open(firmware)
        .with_context(|| format!("open UF2 firmware {}", firmware.display()))?;
    validate_uf2(&mut source)
        .with_context(|| format!("validate UF2 firmware {}", firmware.display()))?;
    source
        .seek(SeekFrom::Start(0))
        .context("rewind UF2 firmware")?;

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .with_context(|| format!("create UF2 on BOOTSEL volume {}", destination.display()))?;
    if let Err(error) = std::io::copy(&mut source, &mut output).and_then(|_| output.sync_all()) {
        let _ = fs::remove_file(&destination);
        return Err(error).with_context(|| format!("copy UF2 to {}", destination.display()));
    }
    drop(output);
    Ok(destination)
}

fn read_u32(block: &[u8; BLOCK_SIZE], offset: usize) -> u32 {
    u32::from_le_bytes([
        block[offset],
        block[offset + 1],
        block[offset + 2],
        block[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uf2_block(block_number: u32, total_blocks: u32, payload_size: u32) -> [u8; BLOCK_SIZE] {
        let mut block = [0u8; BLOCK_SIZE];
        block[0..4].copy_from_slice(&UF2_MAGIC_START0.to_le_bytes());
        block[4..8].copy_from_slice(&UF2_MAGIC_START1.to_le_bytes());
        block[8..12].copy_from_slice(&UF2_FLAG_FAMILY_ID_PRESENT.to_le_bytes());
        block[12..16].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        block[16..20].copy_from_slice(&payload_size.to_le_bytes());
        block[20..24].copy_from_slice(&block_number.to_le_bytes());
        block[24..28].copy_from_slice(&total_blocks.to_le_bytes());
        block[28..32].copy_from_slice(&RP2040_FAMILY_ID.to_le_bytes());
        for (index, byte) in block
            [DATA_START..DATA_START + (payload_size as usize).min(DATA_END - DATA_START)]
            .iter_mut()
            .enumerate()
        {
            *byte = index as u8;
        }
        block[508..512].copy_from_slice(&UF2_MAGIC_END.to_le_bytes());
        block
    }

    #[test]
    fn validates_complete_uf2_and_rejects_bad_blocks() {
        let valid = uf2_block(0, 1, 16);
        assert_eq!(validate_uf2_bytes(&valid).unwrap(), 1);

        let mut bad_magic = valid;
        bad_magic[0] = 0;
        assert!(validate_uf2_bytes(&bad_magic).is_err());
        assert!(validate_uf2_bytes(&uf2_block(0, 1, 477)).is_err());
        let mut missing_family = valid;
        missing_family[8..12].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate_uf2_bytes(&missing_family).is_err());
        let mut wrong_family = valid;
        wrong_family[28..32].copy_from_slice(&0xE48B_FF59u32.to_le_bytes());
        assert!(validate_uf2_bytes(&wrong_family).is_err());

        let duplicate = [uf2_block(0, 2, 16), uf2_block(0, 2, 16)].concat();
        assert!(validate_uf2_bytes(&duplicate).is_err());
        assert!(validate_uf2_bytes(&valid[..valid.len() - 1]).is_err());
    }

    #[test]
    fn copies_only_a_valid_uf2_to_a_bootsel_volume() {
        let temp = tempfile::tempdir().unwrap();
        let mount = temp.path().join("RPI-RP2");
        fs::create_dir(&mount).unwrap();
        fs::write(mount.join("INFO_UF2.TXT"), b"RP2040 BOOTSEL").unwrap();
        let source = temp.path().join("node.uf2");
        let bytes = uf2_block(0, 1, 16);
        fs::write(&source, bytes).unwrap();

        let destination = flash_uf2(&source, &mount).unwrap();
        assert_eq!(destination, mount.join("node.uf2"));
        assert_eq!(fs::read(destination).unwrap(), bytes);
        assert!(
            flash_uf2(&source, &mount).is_err(),
            "do not overwrite an existing UF2"
        );
    }

    #[test]
    fn a_volume_without_info_uf2_txt_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("node.uf2");
        fs::write(&source, uf2_block(0, 1, 16)).unwrap();
        assert!(flash_uf2(&source, temp.path()).is_err());
    }
}
