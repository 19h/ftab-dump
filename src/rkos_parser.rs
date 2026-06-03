//! FTAB container parser (`rkosftab` / `RKOSFTAB`).
//!
//! # Provenance
//!
//! The layout and validation rules implemented here are derived from, and
//! verified against, Apple's on-device FTAB reader `UARPRTKitFTAB`
//! (specifically `-[UARPRTKitFTAB expandFileTable:]`, `-[UARPRTKitFTAB
//! getDataBlock:offset:]`, `-[UARPRTKitFTAB getManifest]`,
//! `-[UARPRTKitFTAB processSubfileInfo:]` and the `UARPRTKitFTABSubfile`
//! accessors), cross-checked against B1N4R1 B01's `rkos.py` and the
//! idevicerestore `ftab.h` description credited in the project readme.
//!
//! # On-disk layout
//!
//! All multi-byte integers are little-endian.
//!
//! Header (48 bytes / `0x30`):
//!
//! | Offset | Size | Field             | Notes                                      |
//! |--------|------|-------------------|--------------------------------------------|
//! | `0x00` | 4    | reserved/unknown  | not read by the device parser              |
//! | `0x04` | 4    | reserved/unknown  | not read by the device parser              |
//! | `0x08` | 8    | reserved/unknown  | not read by the device parser              |
//! | `0x10` | 4    | `manifest_offset` | "ticket" offset (`getManifest`)            |
//! | `0x14` | 4    | `manifest_length` | "ticket" length (`getManifest`)            |
//! | `0x18` | 8    | reserved/unknown  | not read by the device parser              |
//! | `0x20` | 8    | `magic`           | `rkosftab` or `RKOSFTAB`                    |
//! | `0x28` | 4    | `number_of_files` | entry count; `0` is valid (empty table)    |
//! | `0x2C` | 4    | reserved/unknown  | not read by the device parser              |
//!
//! Metadata table: `number_of_files` records of 16 bytes each, starting at
//! `0x30`. Each record:
//!
//! | Offset | Size | Field      | Notes                                      |
//! |--------|------|------------|--------------------------------------------|
//! | `+0x0` | 4    | `tag`      | 4CC; the device decodes it as UTF-8        |
//! | `+0x4` | 4    | `offset`   | absolute payload offset                    |
//! | `+0x8` | 4    | `length`   | payload length                             |
//! | `+0xC` | 4    | reserved   | ignored                                    |
//!
//! # Validation model
//!
//! The device enforces these *hard* requirements (failure aborts the parse):
//!
//! 1. The 48-byte header must be present.
//! 2. The magic at `0x20` must be `rkosftab` or `RKOSFTAB`.
//! 3. Every 16-byte entry record must be fully present, i.e. the whole
//!    metadata table must fit in the file (`0x30 + 16*number_of_files <=
//!    file_len`). The device reads entries one at a time and aborts the moment
//!    a record cannot be read in full.
//!
//! For payloads (and the manifest) the device is *lenient*: `getDataBlock`
//! clamps an out-of-bounds read to the bytes actually available (emitting a
//! "Can only provide N bytes" warning) rather than failing, and an offset at or
//! beyond EOF simply yields an empty block. Zero-length entries are kept (as
//! empty subfiles), not skipped.
//!
//! This parser exposes both behaviours via [`ValidationMode`]:
//!
//! * **Strict** (default): payloads and the manifest must lie fully within the
//!   file, and payloads must start at or after the end of the metadata table.
//!   Any violation is a hard error. This surfaces truncated/corrupt images
//!   instead of silently emitting partial output.
//! * **Lenient**: reproduces the device exactly — payloads/manifest are clamped
//!   to the available bytes and never rejected. Clamping is reported through
//!   [`Ftab::warnings`].

use byteorder::{ByteOrder, LittleEndian};
use std::fmt;

/// Size of the fixed FTAB header, in bytes.
pub const HEADER_SIZE: u64 = 0x30;
/// Size of a single metadata-table record, in bytes.
pub const ENTRY_SIZE: u64 = 16;

/// The two magic values accepted by the device, at file offset `0x20`.
pub const MAGIC_LOWER: &[u8; 8] = b"rkosftab";
pub const MAGIC_UPPER: &[u8; 8] = b"RKOSFTAB";

/// Controls how out-of-bounds payloads and manifests are handled.
#[derive(Clone, Copy, Debug, Default)]
pub struct ValidationMode {
    /// When `true`, reproduce the device's lenient `getDataBlock` behaviour:
    /// clamp out-of-bounds payloads/manifest to the available bytes instead of
    /// rejecting them. When `false` (the default), any out-of-bounds payload or
    /// manifest is a hard error.
    pub lenient: bool,
}

/// A single subfile described by the metadata table.
#[derive(Debug, Clone)]
pub struct FtabEntry {
    /// The raw 4CC tag bytes.
    pub tag: [u8; 4],
    /// The payload offset as declared in the metadata table.
    pub offset: u32,
    /// The payload length as declared in the metadata table.
    pub length: u32,
    /// The bytes actually extracted. Equal in length to `length` unless lenient
    /// mode clamped an out-of-bounds payload, in which case it is shorter.
    pub data: Vec<u8>,
    /// `true` if the payload was clamped because it extended past EOF
    /// (only possible in lenient mode).
    pub truncated: bool,
}

impl FtabEntry {
    /// A human-readable rendering of the tag: the ASCII form if every byte is
    /// printable, otherwise an 8-hex-digit fallback.
    pub fn tag_string(&self) -> String {
        if self.tag.iter().all(|b| (0x20..=0x7E).contains(b)) {
            String::from_utf8_lossy(&self.tag).to_string()
        } else {
            format!(
                "{:02X}{:02X}{:02X}{:02X}",
                self.tag[0], self.tag[1], self.tag[2], self.tag[3]
            )
        }
    }
}

/// A parsed FTAB container.
///
/// Only the fields the device parser actually interprets are surfaced. The
/// header words at `0x00..0x10`, `0x18..0x20` and `0x2C..0x30` are not read by
/// `-[UARPRTKitFTAB expandFileTable:]` and carry no meaning verified by the
/// references, so they are deliberately not exposed under invented names.
pub struct Ftab {
    /// The 8-byte magic at `0x20` (`rkosftab` or `RKOSFTAB`).
    pub magic: [u8; 8],
    /// The declared entry count from `0x28`.
    pub number_of_files: u32,
    /// The manifest ("ticket") blob, if `manifest_length > 0`.
    pub manifest: Option<Vec<u8>>,
    /// The parsed subfile entries (including zero-length ones).
    pub entries: Vec<FtabEntry>,
    /// Non-fatal anomalies encountered while parsing (e.g. clamped payloads in
    /// lenient mode).
    pub warnings: Vec<String>,
}

impl fmt::Debug for Ftab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ftab")
            .field("magic", &String::from_utf8_lossy(&self.magic))
            .field("number_of_files", &self.number_of_files)
            .field("manifest_len", &self.manifest.as_ref().map(|m| m.len()))
            .field("entries", &self.entries.len())
            .field("warnings", &self.warnings.len())
            .finish()
    }
}

/// Errors that abort an FTAB parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtabError {
    /// The buffer is too small to contain a required region.
    Truncated(&'static str),
    /// The magic at `0x20` is neither `rkosftab` nor `RKOSFTAB`.
    InvalidMagic([u8; 8]),
    /// `number_of_files` is so large that the metadata table cannot fit.
    TableOutOfBounds { table_end: u64, file_len: u64 },
    /// (strict mode) The manifest extends past EOF.
    ManifestOutOfBounds { off: u64, len: u64, file_len: u64 },
    /// (strict mode) An entry's payload extends past EOF.
    EntryOutOfBounds {
        idx: usize,
        off: u64,
        len: u64,
        file_len: u64,
    },
    /// (strict mode) An entry's payload starts before the metadata table ends.
    EntryBeforeTable {
        idx: usize,
        off: u64,
        table_end: u64,
    },
}

impl std::error::Error for FtabError {}
impl fmt::Display for FtabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FtabError::*;
        match self {
            Truncated(what) => write!(f, "truncated: {} is incomplete", what),
            InvalidMagic(m) => write!(
                f,
                "invalid magic at 0x20: {:?} (expected \"rkosftab\" or \"RKOSFTAB\")",
                String::from_utf8_lossy(m)
            ),
            TableOutOfBounds {
                table_end,
                file_len,
            } => write!(
                f,
                "metadata table end (0x{:X}) exceeds file length (0x{:X})",
                table_end, file_len
            ),
            ManifestOutOfBounds { off, len, file_len } => write!(
                f,
                "manifest [0x{:X}..0x{:X}] exceeds file length 0x{:X}",
                off,
                off.saturating_add(*len),
                file_len
            ),
            EntryOutOfBounds {
                idx,
                off,
                len,
                file_len,
            } => write!(
                f,
                "entry #{} payload [0x{:X}..0x{:X}] exceeds file length 0x{:X}",
                idx,
                off,
                off.saturating_add(*len),
                file_len
            ),
            EntryBeforeTable {
                idx,
                off,
                table_end,
            } => write!(
                f,
                "entry #{} payload offset 0x{:X} is before the metadata table end 0x{:X}",
                idx, off, table_end
            ),
        }
    }
}

/// Returns `Some((start, end))` as `usize` indices iff `[off, off+len)` lies
/// fully within a buffer of `file_len` bytes. All arithmetic is performed in
/// `u64` and the casts to `usize` are only taken once the range is known to be
/// within `file_len` (which itself equals the buffer length), so this is exact
/// on 32-bit targets and free of overflow/truncation.
fn checked_bounds(file_len: u64, off: u64, len: u64) -> Option<(usize, usize)> {
    let end = off.checked_add(len)?;
    if end > file_len {
        return None;
    }
    Some((off as usize, end as usize))
}

/// Computes the clamped range for a lenient read of `[off, off+len)` against a
/// buffer of `file_len` bytes. Returns the in-bounds `(start, end)` indices and
/// whether the read was truncated. An offset at or beyond EOF yields an empty
/// range.
fn clamped_bounds(file_len: u64, off: u64, len: u64) -> (usize, usize, bool) {
    if off >= file_len {
        // Nothing readable; the whole (possibly non-empty) request is dropped.
        return (0, 0, len > 0);
    }
    let avail = file_len - off;
    let take = len.min(avail);
    let truncated = take < len;
    // `off < file_len` and `off + take <= file_len`, so both casts are exact.
    (off as usize, (off + take) as usize, truncated)
}

/// Parse an FTAB image from the complete file bytes.
///
/// Mirrors `-[UARPRTKitFTAB expandFileTable:]`: it validates the 48-byte
/// header, the magic, and the presence of the full metadata table, then reads
/// each subfile. Payload/manifest bounds handling is governed by `mode`
/// (see [`ValidationMode`]).
pub fn parse_ftab_from_bytes(bytes: &[u8], mode: ValidationMode) -> Result<Ftab, FtabError> {
    let file_len = bytes.len() as u64;

    // (1) The full 48-byte header must be present. The device requires
    // `[getDataBlock:48 offset:0] length == 48`.
    if file_len < HEADER_SIZE {
        return Err(FtabError::Truncated("header (need 48 bytes)"));
    }

    // Header fields (little-endian). Only the fields the device interprets are
    // read; the remaining header words (0x00..0x10, 0x18..0x20, 0x2C..0x30) are
    // reserved/unknown and intentionally left untouched.
    let manifest_offset = LittleEndian::read_u32(&bytes[0x10..0x14]) as u64;
    let manifest_length = LittleEndian::read_u32(&bytes[0x14..0x18]) as u64;

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&bytes[0x20..0x28]);

    let number_of_files = LittleEndian::read_u32(&bytes[0x28..0x2C]);

    // (2) Magic check. The device compares the 8 bytes at 0x20 against the
    // little-endian words 0x42415446534F4B52 ("RKOSFTAB") and
    // 0x62617466736F6B72 ("rkosftab"); those are the only accepted values.
    if &magic != MAGIC_UPPER && &magic != MAGIC_LOWER {
        return Err(FtabError::InvalidMagic(magic));
    }

    // (3) The whole metadata table must fit. `number_of_files == 0` is a valid,
    // empty table per the device (it succeeds with no entries). A count large
    // enough to overflow the file is rejected here, which also bounds every
    // subsequent index and allocation.
    let table_len = (number_of_files as u64) * ENTRY_SIZE;
    let table_end = HEADER_SIZE + table_len; // no overflow: u32*16 + 0x30 < u64::MAX
    if table_end > file_len {
        return Err(FtabError::TableOutOfBounds {
            table_end,
            file_len,
        });
    }

    let mut warnings = Vec::new();

    // Manifest ("ticket"), read at [off=0x10, len=0x14].
    let manifest = parse_manifest(
        bytes,
        file_len,
        manifest_offset,
        manifest_length,
        mode,
        &mut warnings,
    )?;

    // Entries. `number_of_files` is bounded by the table fitting in the file,
    // so this preallocation is bounded by the file size; cap it defensively so
    // a pathologically large (but in-file) count cannot request an absurd
    // allocation up front.
    let mut entries = Vec::with_capacity((number_of_files as usize).min(4096));

    for i in 0..(number_of_files as usize) {
        let rec = HEADER_SIZE as usize + i * ENTRY_SIZE as usize; // within table_end <= file_len
        let tag = [bytes[rec], bytes[rec + 1], bytes[rec + 2], bytes[rec + 3]];
        let payload_off = LittleEndian::read_u32(&bytes[rec + 4..rec + 8]) as u64;
        let payload_len = LittleEndian::read_u32(&bytes[rec + 8..rec + 12]) as u64;
        // bytes[rec+12..rec+16] is reserved and ignored.

        let entry = parse_entry(
            bytes,
            file_len,
            table_end,
            i,
            tag,
            payload_off,
            payload_len,
            mode,
            &mut warnings,
        )?;
        entries.push(entry);
    }

    Ok(Ftab {
        magic,
        number_of_files,
        manifest,
        entries,
        warnings,
    })
}

fn parse_manifest(
    bytes: &[u8],
    file_len: u64,
    off: u64,
    len: u64,
    mode: ValidationMode,
    warnings: &mut Vec<String>,
) -> Result<Option<Vec<u8>>, FtabError> {
    if len == 0 {
        return Ok(None);
    }
    if mode.lenient {
        // The device's `getManifest`/`getDataBlock` returns nil when the
        // manifest offset is at or past EOF, so there is no manifest to surface.
        if off >= file_len {
            warnings.push(format!(
                "manifest offset 0x{:X} is at or past file length 0x{:X}; no manifest data",
                off, file_len
            ));
            return Ok(None);
        }
        let (s, e, truncated) = clamped_bounds(file_len, off, len);
        if truncated {
            warnings.push(format!(
                "manifest [0x{:X}..0x{:X}] exceeds file length 0x{:X}; clamped to {} of {} bytes",
                off,
                off.saturating_add(len),
                file_len,
                e - s,
                len
            ));
        }
        Ok(Some(bytes[s..e].to_vec()))
    } else {
        match checked_bounds(file_len, off, len) {
            Some((s, e)) => Ok(Some(bytes[s..e].to_vec())),
            None => Err(FtabError::ManifestOutOfBounds { off, len, file_len }),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_entry(
    bytes: &[u8],
    file_len: u64,
    table_end: u64,
    idx: usize,
    tag: [u8; 4],
    offset: u64,
    length: u64,
    mode: ValidationMode,
    warnings: &mut Vec<String>,
) -> Result<FtabEntry, FtabError> {
    // A zero-length entry reads no bytes; the device keeps it as an empty
    // subfile regardless of its (unused) offset. Treat it as an empty payload
    // in both modes without bounds-checking the offset.
    if length == 0 {
        return Ok(FtabEntry {
            tag,
            offset: offset as u32,
            length: 0,
            data: Vec::new(),
            truncated: false,
        });
    }

    if mode.lenient {
        let (s, e, truncated) = clamped_bounds(file_len, offset, length);
        if truncated {
            warnings.push(format!(
                "entry #{} payload [0x{:X}..0x{:X}] exceeds file length 0x{:X}; clamped to {} of {} bytes",
                idx,
                offset,
                offset.saturating_add(length),
                file_len,
                e - s,
                length
            ));
        }
        Ok(FtabEntry {
            tag,
            offset: offset as u32,
            length: length as u32,
            data: bytes[s..e].to_vec(),
            truncated,
        })
    } else {
        // Strict integrity: payloads must lie after the metadata table and
        // within the file. (The device does not check the table boundary, but
        // a payload overlapping the header/table is a corruption signal.)
        if offset < table_end {
            return Err(FtabError::EntryBeforeTable {
                idx,
                off: offset,
                table_end,
            });
        }
        match checked_bounds(file_len, offset, length) {
            Some((s, e)) => Ok(FtabEntry {
                tag,
                offset: offset as u32,
                length: length as u32,
                data: bytes[s..e].to_vec(),
                truncated: false,
            }),
            None => Err(FtabError::EntryOutOfBounds {
                idx,
                off: offset,
                len: length,
                file_len,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid FTAB with the given entries `(tag, payload)` and
    /// optional manifest, laying payloads out contiguously after the table.
    fn build_ftab(
        magic: &[u8; 8],
        entries: &[([u8; 4], Vec<u8>)],
        manifest: Option<&[u8]>,
    ) -> Vec<u8> {
        let n = entries.len() as u64;
        let table_end = HEADER_SIZE + n * ENTRY_SIZE;
        // Layout: [header][table][manifest][payloads]
        let mut blob = vec![0u8; HEADER_SIZE as usize];
        blob[0x20..0x28].copy_from_slice(magic);
        LittleEndian::write_u32(&mut blob[0x28..0x2C], entries.len() as u32);

        let mut cursor = table_end;
        let manifest_off = cursor;
        if let Some(m) = manifest {
            cursor += m.len() as u64;
            LittleEndian::write_u32(&mut blob[0x10..0x14], manifest_off as u32);
            LittleEndian::write_u32(&mut blob[0x14..0x18], m.len() as u32);
        }

        // Reserve table region.
        blob.resize(table_end as usize, 0);

        // Append manifest.
        if let Some(m) = manifest {
            blob.extend_from_slice(m);
        }

        // Append payloads and fill the table.
        for (i, (tag, data)) in entries.iter().enumerate() {
            let off = cursor;
            let rec = HEADER_SIZE as usize + i * ENTRY_SIZE as usize;
            blob[rec..rec + 4].copy_from_slice(tag);
            LittleEndian::write_u32(&mut blob[rec + 4..rec + 8], off as u32);
            LittleEndian::write_u32(&mut blob[rec + 8..rec + 12], data.len() as u32);
            blob.extend_from_slice(data);
            cursor += data.len() as u64;
        }
        blob
    }

    #[test]
    fn parses_basic_lowercase_magic() {
        let blob = build_ftab(
            MAGIC_LOWER,
            &[(*b"rkos", vec![1, 2, 3, 4]), (*b"prms", vec![9; 10])],
            None,
        );
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap();
        assert_eq!(ftab.number_of_files, 2);
        assert_eq!(ftab.entries[0].tag, *b"rkos");
        assert_eq!(ftab.entries[0].data, vec![1, 2, 3, 4]);
        assert_eq!(ftab.entries[1].data, vec![9; 10]);
        assert!(ftab.warnings.is_empty());
    }

    #[test]
    fn parses_uppercase_magic() {
        let blob = build_ftab(MAGIC_UPPER, &[(*b"rkos", vec![7, 7])], None);
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap();
        assert_eq!(&ftab.magic, MAGIC_UPPER);
        assert_eq!(ftab.entries[0].data, vec![7, 7]);
    }

    #[test]
    fn rejects_legacy_typo_magic() {
        // "rksoftab" was never a real magic and must be rejected.
        let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1])], None);
        blob[0x20..0x28].copy_from_slice(b"rksoftab");
        let err = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, FtabError::InvalidMagic(_)));
    }

    #[test]
    fn rejects_short_header() {
        let blob = vec![0u8; 16];
        let err = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, FtabError::Truncated(_)));
    }

    #[test]
    fn zero_files_is_valid_and_empty() {
        let blob = build_ftab(MAGIC_LOWER, &[], None);
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap();
        assert_eq!(ftab.number_of_files, 0);
        assert!(ftab.entries.is_empty());
    }

    #[test]
    fn high_file_count_above_legacy_cap_is_accepted_when_table_fits() {
        // 200 zero-length entries: the old 1..=127 cap would have rejected this.
        let entries: Vec<([u8; 4], Vec<u8>)> = (0..200).map(|_| (*b"zero", Vec::new())).collect();
        let blob = build_ftab(MAGIC_LOWER, &entries, None);
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap();
        assert_eq!(ftab.entries.len(), 200);
        assert!(ftab.entries.iter().all(|e| e.data.is_empty()));
    }

    #[test]
    fn table_overflowing_file_is_rejected() {
        let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1])], None);
        // Claim a huge entry count that cannot fit.
        LittleEndian::write_u32(&mut blob[0x28..0x2C], 0x0FFF_FFFF);
        let err = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, FtabError::TableOutOfBounds { .. }));
    }

    #[test]
    fn zero_length_entries_are_kept() {
        let blob = build_ftab(
            MAGIC_LOWER,
            &[
                (*b"aaaa", vec![1, 2]),
                (*b"bbbb", Vec::new()),
                (*b"cccc", vec![3]),
            ],
            None,
        );
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap();
        assert_eq!(ftab.entries.len(), 3);
        assert_eq!(ftab.entries[1].tag, *b"bbbb");
        assert!(ftab.entries[1].data.is_empty());
    }

    #[test]
    fn manifest_is_extracted() {
        let blob = build_ftab(
            MAGIC_LOWER,
            &[(*b"rkos", vec![1])],
            Some(&[0xDE, 0xAD, 0xBE, 0xEF]),
        );
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap();
        assert_eq!(
            ftab.manifest.as_deref(),
            Some(&[0xDE, 0xAD, 0xBE, 0xEF][..])
        );
    }

    #[test]
    fn strict_rejects_out_of_bounds_payload() {
        let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1, 2, 3, 4])], None);
        // Inflate the declared length past EOF.
        let rec = HEADER_SIZE as usize;
        LittleEndian::write_u32(&mut blob[rec + 8..rec + 12], 0xFFFF);
        let err = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, FtabError::EntryOutOfBounds { idx: 0, .. }));
    }

    #[test]
    fn lenient_clamps_out_of_bounds_payload() {
        let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1, 2, 3, 4])], None);
        let rec = HEADER_SIZE as usize;
        LittleEndian::write_u32(&mut blob[rec + 8..rec + 12], 0xFFFF);
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode { lenient: true }).unwrap();
        assert_eq!(ftab.entries[0].data, vec![1, 2, 3, 4]);
        assert!(ftab.entries[0].truncated);
        assert_eq!(ftab.entries[0].length, 0xFFFF);
        assert_eq!(ftab.warnings.len(), 1);
    }

    #[test]
    fn strict_rejects_payload_before_table() {
        let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1, 2, 3, 4])], None);
        // Point the payload at the header.
        let rec = HEADER_SIZE as usize;
        LittleEndian::write_u32(&mut blob[rec + 4..rec + 8], 0x10);
        let err = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, FtabError::EntryBeforeTable { idx: 0, .. }));
    }

    #[test]
    fn strict_rejects_out_of_bounds_manifest() {
        let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1])], None);
        LittleEndian::write_u32(&mut blob[0x10..0x14], 0x30);
        LittleEndian::write_u32(&mut blob[0x14..0x18], 0xFFFF);
        let err = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap_err();
        assert!(matches!(err, FtabError::ManifestOutOfBounds { .. }));
    }

    #[test]
    fn lenient_manifest_offset_past_eof_is_none() {
        let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1])], None);
        // Point the manifest entirely past EOF.
        let past = blob.len() as u32 + 0x100;
        LittleEndian::write_u32(&mut blob[0x10..0x14], past);
        LittleEndian::write_u32(&mut blob[0x14..0x18], 16);
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode { lenient: true }).unwrap();
        assert!(ftab.manifest.is_none());
        assert_eq!(ftab.warnings.len(), 1);
    }

    #[test]
    fn lenient_manifest_overrun_is_clamped() {
        // Lay the manifest out as the final region so a clamped overrun maps to
        // exactly its real bytes (nothing trails it in the file).
        let mut blob = vec![0u8; HEADER_SIZE as usize];
        blob[0x20..0x28].copy_from_slice(MAGIC_LOWER);
        LittleEndian::write_u32(&mut blob[0x28..0x2C], 1);
        blob.resize(HEADER_SIZE as usize + ENTRY_SIZE as usize, 0); // table

        let payload_off = blob.len() as u32;
        blob.push(0x11); // 1-byte payload for the single entry
        let rec = HEADER_SIZE as usize;
        blob[rec..rec + 4].copy_from_slice(b"rkos");
        LittleEndian::write_u32(&mut blob[rec + 4..rec + 8], payload_off);
        LittleEndian::write_u32(&mut blob[rec + 8..rec + 12], 1);

        let manifest_off = blob.len() as u32;
        blob.extend_from_slice(&[0xAA, 0xBB]); // 2 real manifest bytes at EOF
        LittleEndian::write_u32(&mut blob[0x10..0x14], manifest_off);
        LittleEndian::write_u32(&mut blob[0x14..0x18], 0xFFFF); // declared overrun

        let ftab = parse_ftab_from_bytes(&blob, ValidationMode { lenient: true }).unwrap();
        assert_eq!(ftab.manifest.as_deref(), Some(&[0xAA, 0xBB][..]));
        assert_eq!(ftab.warnings.len(), 1);
    }

    #[test]
    fn checked_bounds_is_overflow_safe() {
        // off + len overflows u64 -> None, never panics.
        assert_eq!(checked_bounds(100, u64::MAX, 10), None);
        assert_eq!(checked_bounds(100, 10, u64::MAX), None);
        assert_eq!(checked_bounds(100, 10, 20), Some((10, 30)));
        assert_eq!(checked_bounds(100, 90, 11), None);
        assert_eq!(checked_bounds(100, 90, 10), Some((90, 100)));
    }

    #[test]
    fn clamped_bounds_handles_offset_past_eof() {
        assert_eq!(clamped_bounds(100, 200, 10), (0, 0, true));
        assert_eq!(clamped_bounds(100, 90, 50), (90, 100, true));
        assert_eq!(clamped_bounds(100, 10, 20), (10, 30, false));
    }
}
