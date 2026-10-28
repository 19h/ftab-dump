//! FTAB container parser (`rkosftab` / `RKOSFTAB`).
//!
//! The on-disk layout below is derived from the FTAB implementations shipped in
//! Apple's updater libraries (`libauthinstall.dylib`, `libAppleTconUARPUpdater.dylib`)
//! and cross-checked against `idevicerestore`'s `ftab.h`:
//!
//! ```text
//! offset  size  field
//! 0x00    4     generation      (device-specific version word)
//! 0x04    4     valid           (normally 0xFFFFFFFF)
//! 0x08    8     boot nonce
//! 0x10    4     manifest offset
//! 0x14    4     manifest length
//! 0x18    4     reserved        (zero)
//! 0x1C    4     reserved        (zero)
//! 0x20    8     magic           ("rkosftab" / "RKOSFTAB")
//! 0x28    4     number of files (zero is valid)
//! 0x2C    4     reserved        (zero)
//! 0x30    16*N  file table
//! ```
//!
//! Each file-table entry is:
//!
//! ```text
//! offset  size  field
//! 0x00    4     tag (four-character code, never NUL terminated on disk)
//! 0x04    4     payload offset (absolute, little endian)
//! 0x08    4     payload length (little endian)
//! 0x0C    4     reserved (zero)
//! ```
//!
//! Payloads and the manifest (the personalization ticket, an opaque IM4M blob)
//! are 4-byte aligned; Apple pads the gaps with zeroes. The manifest may be
//! placed directly after the file table ("at the top") or after the payloads
//! ("at the end"); the header records where it lives.
//!
//! Header and file-table bounds, magic validation, and lenient clamping follow
//! the on-device `UARPRTKitFTAB` reader. The entry count is bounded by the table
//! fitting in the image; empty tables are valid. Default parsing rejects
//! out-of-bounds reads and non-empty payloads overlapping the table. Lenient
//! parsing clamps reads to available bytes and reports truncation. Manifest
//! placement, alignment, reserved words, and cross-entry quirks are reported
//! as diagnostics for inspection.

use byteorder::{ByteOrder, LittleEndian};
use std::collections::BTreeMap;
use std::fmt;

/// Size of the fixed FTAB header.
pub const HEADER_SIZE: u64 = 0x30;
/// Size of one file-table entry.
pub const ENTRY_SIZE: u64 = 0x10;
/// The two magic values accepted by the on-device reader.
pub const MAGIC_LOWER: &[u8; 8] = b"rkosftab";
pub const MAGIC_UPPER: &[u8; 8] = b"RKOSFTAB";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ValidationMode {
    /// Clamp payloads and manifests to available bytes, matching the on-device
    /// reader. The complete header and file table are required in every mode.
    pub lenient: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MagicVariant {
    RkosFtab,
    RkosFtabUpper,
}

impl MagicVariant {
    pub fn as_str(self) -> &'static str {
        match self {
            MagicVariant::RkosFtab => "rkosftab",
            MagicVariant::RkosFtabUpper => "RKOSFTAB",
        }
    }
}

#[derive(Clone, Debug)]
pub struct FtabHeader {
    /// Generation/version word. Apple logs this as "Generation"; it is not
    /// always 1 (e.g. some UARP FTABs use 0x09000100).
    pub generation: u32,
    pub valid_flag: u32,
    pub boot_nonce: u64,
    pub manifest_offset: u32,
    pub manifest_length: u32,
    /// Header word at 0x18. Apple writes zero.
    pub reserved_18: u32,
    /// Header word at 0x1C. Apple writes zero.
    pub reserved_1c: u32,
    pub magic: [u8; 8],
    pub number_of_files: u32,
    /// Header word at 0x2C. Apple writes zero.
    pub reserved_2c: u32,
}

impl FtabHeader {
    pub fn magic_variant(&self) -> Option<MagicVariant> {
        magic_variant(&self.magic)
    }

    pub fn file_table_end(&self) -> u64 {
        HEADER_SIZE + (self.number_of_files as u64) * ENTRY_SIZE
    }
}

#[derive(Clone)]
pub struct FtabEntry {
    pub tag: [u8; 4],
    pub offset: u32,
    pub length: u32,
    /// Entry word at 0x0C. Apple writes zero.
    pub reserved: u32,
    /// Available payload bytes, clamped to EOF in lenient mode.
    pub data: Vec<u8>,
    pub truncated: bool,
}

impl FtabEntry {
    pub fn tag_string(&self) -> String {
        if self.is_printable_tag() {
            String::from_utf8_lossy(&self.tag).to_string()
        } else {
            format!(
                "{:02X}{:02X}{:02X}{:02X}",
                self.tag[0], self.tag[1], self.tag[2], self.tag[3]
            )
        }
    }

    pub fn is_printable_tag(&self) -> bool {
        self.tag.iter().all(|b| (0x20..=0x7E).contains(b))
    }

    /// Zero-length table slots are placeholders; Apple keeps them in the table
    /// but their offset carries no payload.
    pub fn is_placeholder(&self) -> bool {
        self.length == 0
    }

    pub fn end_offset(&self) -> u64 {
        self.offset as u64 + self.length as u64
    }
}

impl fmt::Debug for FtabEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FtabEntry")
            .field("tag", &self.tag_string())
            .field("offset", &self.offset)
            .field("length", &self.length)
            .field("reserved", &self.reserved)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestPlacement {
    /// Directly after the file table, before any payload.
    BeforePayloads,
    /// Immediately after the last payload.
    AfterPayloads,
    /// Somewhere between payloads (unusual but legal).
    BetweenPayloads,
    /// The manifest range overlaps at least one payload.
    OverlapsPayload,
    /// Manifest present but there are no payloads to compare against.
    NoPayloads,
}

impl ManifestPlacement {
    pub fn as_str(self) -> &'static str {
        match self {
            ManifestPlacement::BeforePayloads => "before payloads",
            ManifestPlacement::AfterPayloads => "after payloads",
            ManifestPlacement::BetweenPayloads => "between payloads",
            ManifestPlacement::OverlapsPayload => "overlapping payloads",
            ManifestPlacement::NoPayloads => "no payloads",
        }
    }
}

#[derive(Clone)]
pub struct FtabManifest {
    pub offset: u32,
    pub length: u32,
    pub placement: ManifestPlacement,
    pub data: Option<Vec<u8>>,
}

impl FtabManifest {
    pub fn end_offset(&self) -> u64 {
        self.offset as u64 + self.length as u64
    }
}

impl fmt::Debug for FtabManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FtabManifest")
            .field("offset", &self.offset)
            .field("length", &self.length)
            .field("placement", &self.placement)
            .field("data_len", &self.data.as_ref().map(Vec::len))
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FtabWarning {
    /// Bounds diagnostics from the on-device-compatible lenient reader.
    TruncatedRead(String),
    ManifestBeforeTable {
        off: u64,
        table_end: u64,
    },
    EntryBeforeTable {
        index: usize,
        off: u64,
        table_end: u64,
    },
    UnexpectedValidFlag(u32),
    ReservedHeaderNonZero {
        offset: u64,
        value: u32,
    },
    ManifestOffsetWithoutLength(u32),
    ManifestMisaligned {
        offset: u32,
    },
    ManifestOverlapsPayload {
        entry: usize,
    },
    EntryMisaligned {
        index: usize,
        offset: u32,
    },
    EntryReservedNonZero {
        index: usize,
        value: u32,
    },
    ZeroLengthPlaceholderOffsetOutOfRange {
        index: usize,
        offset: u32,
    },
    EntryOutOfOrder {
        previous: usize,
        index: usize,
    },
    EntriesOverlap {
        first: usize,
        second: usize,
    },
    DuplicateTag {
        first: usize,
        second: usize,
        tag: String,
    },
}

impl fmt::Display for FtabWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FtabWarning::*;

        match self {
            TruncatedRead(message) => f.write_str(message),
            ManifestBeforeTable { off, table_end } => write!(
                f,
                "manifest offset 0x{:X} is before table_end 0x{:X}",
                off, table_end
            ),
            EntryBeforeTable {
                index,
                off,
                table_end,
            } => write!(
                f,
                "entry #{} offset 0x{:X} is before table_end 0x{:X}",
                index, off, table_end
            ),
            UnexpectedValidFlag(v) => write!(
                f,
                "unexpected valid flag 0x{:08X} (Apple writes 0xFFFFFFFF)",
                v
            ),
            ReservedHeaderNonZero { offset, value } => write!(
                f,
                "reserved header word at 0x{:X} is non-zero: 0x{:08X}",
                offset, value
            ),
            ManifestOffsetWithoutLength(off) => write!(
                f,
                "manifest offset is 0x{:X} but manifest length is zero",
                off
            ),
            ManifestMisaligned { offset } => {
                write!(f, "manifest offset 0x{:X} is not 4-byte aligned", offset)
            }
            ManifestOverlapsPayload { entry } => write!(f, "manifest overlaps payload #{}", entry),
            EntryMisaligned { index, offset } => write!(
                f,
                "payload #{} offset 0x{:X} is not 4-byte aligned",
                index, offset
            ),
            EntryReservedNonZero { index, value } => write!(
                f,
                "payload #{} reserved word is non-zero: 0x{:08X}",
                index, value
            ),
            ZeroLengthPlaceholderOffsetOutOfRange { index, offset } => write!(
                f,
                "zero-length placeholder #{} has out-of-range offset 0x{:X}",
                index, offset
            ),
            EntryOutOfOrder { previous, index } => {
                write!(f, "payload #{} starts before payload #{}", index, previous)
            }
            EntriesOverlap { first, second } => {
                write!(f, "payload #{} overlaps payload #{}", first, second)
            }
            DuplicateTag { first, second, tag } => {
                write!(f, "payloads #{} and #{} share tag {:?}", first, second, tag)
            }
        }
    }
}

pub struct Ftab {
    pub header: FtabHeader,
    pub magic_variant: MagicVariant,
    pub manifest: Option<FtabManifest>,
    pub entries: Vec<FtabEntry>,
    pub warnings: Vec<FtabWarning>,
}

impl Ftab {
    pub fn file_table_end(&self) -> u64 {
        self.header.file_table_end()
    }

    pub fn payload_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.is_placeholder()).count()
    }

    pub fn placeholder_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_placeholder()).count()
    }

    pub fn payload_bytes(&self) -> u64 {
        self.entries.iter().map(|e| e.length as u64).sum()
    }

    /// Lowest/highest occupied payload byte, if any.
    pub fn payload_span(&self) -> Option<(u64, u64)> {
        let mut span: Option<(u64, u64)> = None;
        for entry in self.entries.iter().filter(|e| !e.is_placeholder()) {
            let start = entry.offset as u64;
            let end = entry.end_offset();
            span = Some(match span {
                Some((lo, hi)) => (lo.min(start), hi.max(end)),
                None => (start, end),
            });
        }
        span
    }
}

impl fmt::Debug for Ftab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ftab")
            .field("generation", &self.header.generation)
            .field("valid_flag", &self.header.valid_flag)
            .field(
                "boot_nonce",
                &format_args!("0x{:016X}", self.header.boot_nonce),
            )
            .field("magic", &String::from_utf8_lossy(&self.header.magic))
            .field("number_of_files", &self.header.number_of_files)
            .field("manifest", &self.manifest)
            .field("entries", &self.entries.len())
            .field("warnings", &self.warnings.len())
            .finish()
    }
}

#[derive(Debug)]
pub enum FtabError {
    Truncated(&'static str),
    InvalidMagic([u8; 8]),
    TableOutOfBounds {
        table_end: u64,
        file_len: u64,
    },
    ManifestOutOfBounds {
        off: u64,
        len: u64,
        file_len: u64,
    },
    EntryOutOfBounds {
        idx: usize,
        off: u64,
        len: u64,
        file_len: u64,
    },
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

fn magic_variant(magic: &[u8; 8]) -> Option<MagicVariant> {
    if magic == MAGIC_LOWER {
        Some(MagicVariant::RkosFtab)
    } else if magic == MAGIC_UPPER {
        Some(MagicVariant::RkosFtabUpper)
    } else {
        None
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
    reserved: u32,
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
            reserved,
            data: Vec::new(),
            truncated: false,
        });
    }

    if mode.lenient {
        let (s, e, truncated) = clamped_bounds(file_len, offset, length);
        if truncated {
            // Distinguish "offset at/past EOF" (the device's getDataBlock returns
            // nil with no clamp warning) from a genuine partial overrun, so the
            // message is accurate rather than reporting a bogus "clamped to 0".
            if e == s {
                warnings.push(format!(
                    "entry #{} payload offset 0x{:X} is at or past file length 0x{:X}; 0 of {} bytes available",
                    idx, offset, file_len, length
                ));
            } else {
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
        }
        Ok(FtabEntry {
            tag,
            offset: offset as u32,
            length: length as u32,
            reserved,
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
                reserved,
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

fn read_u32(bytes: &[u8], off: usize) -> u32 {
    LittleEndian::read_u32(&bytes[off..off + 4])
}

/// Parse and validate a complete FTAB image.
///
/// See the module docs for the layout and validation policy. Structural
/// oddities are returned in
/// [`Ftab::warnings`].
pub fn parse_ftab_from_bytes(bytes: &[u8], mode: ValidationMode) -> Result<Ftab, FtabError> {
    if bytes.len() < HEADER_SIZE as usize {
        return Err(FtabError::Truncated("header (need 48 bytes)"));
    }

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&bytes[0x20..0x28]);

    let header = FtabHeader {
        generation: read_u32(bytes, 0x00),
        valid_flag: read_u32(bytes, 0x04),
        boot_nonce: LittleEndian::read_u64(&bytes[0x08..0x10]),
        manifest_offset: read_u32(bytes, 0x10),
        manifest_length: read_u32(bytes, 0x14),
        reserved_18: read_u32(bytes, 0x18),
        reserved_1c: read_u32(bytes, 0x1C),
        magic,
        number_of_files: read_u32(bytes, 0x28),
        reserved_2c: read_u32(bytes, 0x2C),
    };

    let magic_variant = header
        .magic_variant()
        .ok_or(FtabError::InvalidMagic(header.magic))?;

    let file_len = bytes.len() as u64;
    let table_start = HEADER_SIZE;
    let table_end = header.file_table_end();

    if table_end > file_len {
        return Err(FtabError::TableOutOfBounds {
            table_end,
            file_len,
        });
    }

    let mut warnings = Vec::new();

    if header.valid_flag != u32::MAX {
        warnings.push(FtabWarning::UnexpectedValidFlag(header.valid_flag));
    }
    for (offset, value) in [
        (0x18u64, header.reserved_18),
        (0x1Cu64, header.reserved_1c),
        (0x2Cu64, header.reserved_2c),
    ] {
        if value != 0 {
            warnings.push(FtabWarning::ReservedHeaderNonZero { offset, value });
        }
    }

    // Retain the declared manifest metadata for inspection, including when
    // lenient reads cannot recover any data at or beyond EOF.
    let mut manifest = None;
    if header.manifest_length > 0 {
        let off = header.manifest_offset as u64;
        let len = header.manifest_length as u64;
        let mut bounds_warnings = Vec::new();
        let data = parse_manifest(bytes, file_len, off, len, mode, &mut bounds_warnings)?;
        warnings.extend(bounds_warnings.into_iter().map(FtabWarning::TruncatedRead));
        if off < table_end {
            warnings.push(FtabWarning::ManifestBeforeTable { off, table_end });
        }
        if header.manifest_offset % 4 != 0 {
            warnings.push(FtabWarning::ManifestMisaligned {
                offset: header.manifest_offset,
            });
        }
        manifest = Some(FtabManifest {
            offset: header.manifest_offset,
            length: header.manifest_length,
            placement: ManifestPlacement::NoPayloads,
            data,
        });
    } else if header.manifest_offset != 0 {
        warnings.push(FtabWarning::ManifestOffsetWithoutLength(
            header.manifest_offset,
        ));
    }

    let mut entries = Vec::with_capacity((header.number_of_files as usize).min(4096));

    for i in 0..header.number_of_files as usize {
        let entry_off = table_start as usize + i * ENTRY_SIZE as usize;
        let mut tag = [0u8; 4];
        tag.copy_from_slice(&bytes[entry_off..entry_off + 4]);

        let payload_off = read_u32(bytes, entry_off + 4);
        let payload_len = read_u32(bytes, entry_off + 8);
        let reserved = read_u32(bytes, entry_off + 0xC);

        if reserved != 0 {
            warnings.push(FtabWarning::EntryReservedNonZero {
                index: i,
                value: reserved,
            });
        }

        if payload_len == 0 {
            // Placeholders carry no payload. Older images occasionally leave
            // a bogus offset here, so only flag it instead of failing.
            if payload_off != 0
                && ((payload_off as u64) < table_end || payload_off as u64 > file_len)
            {
                warnings.push(FtabWarning::ZeroLengthPlaceholderOffsetOutOfRange {
                    index: i,
                    offset: payload_off,
                });
            }
            entries.push(FtabEntry {
                tag,
                offset: payload_off,
                length: 0,
                reserved,
                data: Vec::new(),
                truncated: false,
            });
            continue;
        }

        let off = payload_off as u64;
        let length = payload_len as u64;
        let mut bounds_warnings = Vec::new();
        let entry = parse_entry(
            bytes,
            file_len,
            table_end,
            i,
            tag,
            reserved,
            off,
            length,
            mode,
            &mut bounds_warnings,
        )?;
        warnings.extend(bounds_warnings.into_iter().map(FtabWarning::TruncatedRead));
        if mode.lenient && off < table_end {
            warnings.push(FtabWarning::EntryBeforeTable {
                index: i,
                off,
                table_end,
            });
        }
        if payload_off % 4 != 0 {
            warnings.push(FtabWarning::EntryMisaligned {
                index: i,
                offset: payload_off,
            });
        }
        entries.push(entry);
    }

    // Cross-entry diagnostics use O(n log n) time and O(n) auxiliary space
    // for n entries, emitting at most one overlap witness per payload.
    let mut sorted: Vec<(usize, u64, u64)> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.is_placeholder())
        .map(|(i, e)| (i, e.offset as u64, e.end_offset()))
        .collect();
    sorted.sort_by_key(|&(_, start, _)| start);

    // Track the furthest end rather than only the preceding entry: a short
    // nested range must not hide overlaps with an earlier, longer payload.
    let mut furthest: Option<(usize, u64)> = None;
    for &(index, start, end) in &sorted {
        if let Some((first, first_end)) = furthest {
            if start < first_end {
                warnings.push(FtabWarning::EntriesOverlap {
                    first,
                    second: index,
                });
            }
            if end > first_end {
                furthest = Some((index, end));
            }
        } else {
            furthest = Some((index, end));
        }
    }

    let mut previous: Option<(usize, u64)> = None;
    for (index, entry) in entries.iter().enumerate() {
        if entry.is_placeholder() {
            continue;
        }
        let start = entry.offset as u64;
        if let Some((prev_index, prev_start)) = previous {
            if start < prev_start {
                warnings.push(FtabWarning::EntryOutOfOrder {
                    previous: prev_index,
                    index,
                });
            }
        }
        previous = Some((index, start));
    }

    let mut seen: BTreeMap<[u8; 4], usize> = BTreeMap::new();
    for (index, entry) in entries.iter().enumerate() {
        if entry.is_placeholder() {
            continue;
        }
        if let Some(&first) = seen.get(&entry.tag) {
            warnings.push(FtabWarning::DuplicateTag {
                first,
                second: index,
                tag: entry.tag_string(),
            });
        } else {
            seen.insert(entry.tag, index);
        }
    }

    // Classify where the manifest lives and whether it collides with a payload.
    if let Some(manifest) = manifest.as_mut() {
        let manifest_start = manifest.offset as u64;
        let manifest_end = manifest.end_offset();
        let overlap = sorted
            .iter()
            .find(|&&(_, start, end)| manifest_start < end && start < manifest_end)
            .map(|&(index, _, _)| index);

        if let Some(entry) = overlap {
            warnings.push(FtabWarning::ManifestOverlapsPayload { entry });
            manifest.placement = ManifestPlacement::OverlapsPayload;
        } else if sorted.is_empty() {
            manifest.placement = ManifestPlacement::NoPayloads;
        } else {
            let min_start = sorted.first().map(|&(_, start, _)| start).unwrap_or(0);
            let max_end = sorted.iter().map(|&(_, _, end)| end).max().unwrap_or(0);
            manifest.placement = if manifest_end <= min_start {
                ManifestPlacement::BeforePayloads
            } else if manifest_start >= max_end {
                ManifestPlacement::AfterPayloads
            } else {
                ManifestPlacement::BetweenPayloads
            };
        }
    }

    Ok(Ftab {
        header,
        magic_variant,
        manifest,
        entries,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(
        files: &[(&[u8; 4], u32, u32)],
        manifest: Option<(u32, u32)>,
        file_len: usize,
    ) -> Vec<u8> {
        let needed = 0x30 + files.len() * 0x10;
        let mut bytes = vec![0u8; file_len.max(needed)];
        LittleEndian::write_u32(&mut bytes[0x00..0x04], 1);
        LittleEndian::write_u32(&mut bytes[0x04..0x08], u32::MAX);
        LittleEndian::write_u64(&mut bytes[0x08..0x10], 0x1122334455667788);
        let (manifest_offset, manifest_length) = manifest.unwrap_or((0, 0));
        LittleEndian::write_u32(&mut bytes[0x10..0x14], manifest_offset);
        LittleEndian::write_u32(&mut bytes[0x14..0x18], manifest_length);
        bytes[0x20..0x28].copy_from_slice(MAGIC_LOWER);
        LittleEndian::write_u32(&mut bytes[0x28..0x2C], files.len() as u32);
        for (i, (tag, offset, length)) in files.iter().enumerate() {
            let base = 0x30 + i * 0x10;
            bytes[base..base + 4].copy_from_slice(&tag[..]);
            LittleEndian::write_u32(&mut bytes[base + 4..base + 8], *offset);
            LittleEndian::write_u32(&mut bytes[base + 8..base + 0xC], *length);
        }
        bytes
    }

    #[test]
    fn parses_minimal_image() {
        let mut bytes = image(&[(b"test", 0x40, 4)], None, 0x44);
        bytes[0x40..0x44].copy_from_slice(b"abcd");

        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert_eq!(ftab.header.generation, 1);
        assert_eq!(ftab.header.boot_nonce, 0x1122334455667788);
        assert_eq!(ftab.magic_variant, MagicVariant::RkosFtab);
        assert_eq!(ftab.entries.len(), 1);
        assert_eq!(ftab.entries[0].tag_string(), "test");
        assert_eq!(ftab.entries[0].data, b"abcd");
        assert!(ftab.warnings.is_empty(), "{:?}", ftab.warnings);
    }

    #[test]
    fn accepts_device_specific_generation_word() {
        // Real UARP FTABs (e.g. FTAB_1 from Firmware.acsw) carry 0x09000100
        // here rather than 1.
        let mut bytes = image(&[(b"test", 0x40, 4)], None, 0x44);
        LittleEndian::write_u32(&mut bytes[0x00..0x04], 0x0900_0100);
        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert_eq!(ftab.header.generation, 0x0900_0100);
        assert!(ftab.warnings.is_empty(), "{:?}", ftab.warnings);
    }

    #[test]
    fn classifies_manifest_after_payloads() {
        let mut bytes = image(&[(b"test", 0x40, 4)], Some((0x44, 4)), 0x48);
        bytes[0x40..0x44].copy_from_slice(b"abcd");
        bytes[0x44..0x48].copy_from_slice(b"MNFT");

        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        let manifest = ftab.manifest.unwrap();
        assert_eq!(manifest.placement, ManifestPlacement::AfterPayloads);
        assert_eq!(manifest.data.unwrap(), b"MNFT");
    }

    #[test]
    fn classifies_manifest_before_payloads() {
        let mut bytes = image(&[(b"test", 0x44, 4)], Some((0x40, 4)), 0x48);
        bytes[0x40..0x44].copy_from_slice(b"MNFT");
        bytes[0x44..0x48].copy_from_slice(b"abcd");

        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert_eq!(
            ftab.manifest.unwrap().placement,
            ManifestPlacement::BeforePayloads
        );
    }

    #[test]
    fn keeps_zero_length_placeholders() {
        let bytes = image(&[(b"test", 0, 0), (b"data", 0x50, 1)], None, 0x51);
        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert_eq!(ftab.entries.len(), 2);
        assert!(ftab.entries[0].is_placeholder());
        assert_eq!(ftab.payload_count(), 1);
        assert_eq!(ftab.placeholder_count(), 1);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = image(&[(b"test", 0x40, 1)], None, 0x41);
        bytes[0x20..0x28].copy_from_slice(b"nope    ");
        assert!(matches!(
            parse_ftab_from_bytes(&bytes, ValidationMode::default()),
            Err(FtabError::InvalidMagic(_))
        ));
    }

    #[test]
    fn accepts_empty_table_and_rejects_incomplete_table() {
        let bytes = image(&[], None, 0x30);
        assert!(parse_ftab_from_bytes(&bytes, ValidationMode::default())
            .unwrap()
            .entries
            .is_empty());
        let mut bytes = image(&[(b"test", 0x40, 0)], None, 0x40);
        LittleEndian::write_u32(&mut bytes[0x28..0x2C], u32::MAX);
        assert!(matches!(
            parse_ftab_from_bytes(&bytes, ValidationMode::default()),
            Err(FtabError::TableOutOfBounds { .. })
        ));
    }

    #[test]
    fn rejects_table_out_of_bounds() {
        let bytes = image(&[(b"test", 0x40, 0)], None, 0x40);
        assert!(matches!(
            parse_ftab_from_bytes(&bytes[..0x38], ValidationMode::default()),
            Err(FtabError::TableOutOfBounds { .. })
        ));
    }

    #[test]
    fn rejects_entry_before_table() {
        let bytes = image(&[(b"test", 0x20, 1)], None, 0x40);
        assert!(matches!(
            parse_ftab_from_bytes(&bytes, ValidationMode::default()),
            Err(FtabError::EntryBeforeTable { .. })
        ));
    }

    #[test]
    fn rejects_entry_out_of_bounds() {
        let bytes = image(&[(b"test", 0x40, 8)], None, 0x44);
        assert!(matches!(
            parse_ftab_from_bytes(&bytes, ValidationMode::default()),
            Err(FtabError::EntryOutOfBounds { .. })
        ));
    }

    #[test]
    fn lenient_clamps_out_of_bounds_payloads() {
        let bytes = image(&[(b"test", 0x40, 8)], None, 0x44);
        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode { lenient: true }).unwrap();
        assert_eq!(ftab.entries[0].length, 8);
        assert_eq!(ftab.entries[0].data, vec![0; 4]);
        assert!(ftab.entries[0].truncated);
    }

    #[test]
    fn warns_on_manifest_before_table() {
        let bytes = image(&[(b"test", 0x40, 0)], Some((0x20, 4)), 0x44);
        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert!(ftab
            .warnings
            .iter()
            .any(|w| matches!(w, FtabWarning::ManifestBeforeTable { .. })));
    }

    #[test]
    fn detects_overlaps_across_nested_ranges() {
        let bytes = image(
            &[
                (b"aaaa", 0x60, 0x40),
                (b"bbbb", 0x64, 4),
                (b"cccc", 0x70, 4),
            ],
            None,
            0xA0,
        );
        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert!(ftab.warnings.iter().any(|w| matches!(
            w,
            FtabWarning::EntriesOverlap {
                first: 0,
                second: 2
            }
        )));
    }

    #[test]
    fn accepts_counts_above_host_updater_limit_when_table_fits() {
        let entries = vec![(b"zero", 0, 0); 0x4000];
        let bytes = image(&entries, None, 0);
        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert_eq!(ftab.entries.len(), entries.len());
    }

    #[test]
    fn warns_on_misalignment_and_overlap() {
        let bytes = image(
            &[(b"aaaa", 0x51, 4), (b"bbbb", 0x53, 4)],
            Some((0x55, 2)),
            0x57,
        );
        let ftab = parse_ftab_from_bytes(&bytes, ValidationMode::default()).unwrap();
        assert!(ftab
            .warnings
            .iter()
            .any(|w| matches!(w, FtabWarning::EntryMisaligned { .. })));
        assert!(ftab
            .warnings
            .iter()
            .any(|w| matches!(w, FtabWarning::EntriesOverlap { .. })));
        assert!(ftab
            .warnings
            .iter()
            .any(|w| matches!(w, FtabWarning::ManifestOverlapsPayload { .. })));
    }
}

#[cfg(test)]
mod device_reader_tests {
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
        assert_eq!(ftab.header.number_of_files, 2);
        assert_eq!(ftab.entries[0].tag, *b"rkos");
        assert_eq!(ftab.entries[0].data, vec![1, 2, 3, 4]);
        assert_eq!(ftab.entries[1].data, vec![9; 10]);
        assert!(!ftab
            .warnings
            .iter()
            .any(|w| matches!(w, FtabWarning::TruncatedRead(_))));
    }

    #[test]
    fn parses_uppercase_magic() {
        let blob = build_ftab(MAGIC_UPPER, &[(*b"rkos", vec![7, 7])], None);
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode::default()).unwrap();
        assert_eq!(&ftab.header.magic, MAGIC_UPPER);
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
        assert_eq!(ftab.header.number_of_files, 0);
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
            ftab.manifest.as_ref().and_then(|m| m.data.as_deref()),
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
        assert_eq!(
            ftab.warnings
                .iter()
                .filter(|w| matches!(w, FtabWarning::TruncatedRead(_)))
                .count(),
            1
        );
    }

    #[test]
    fn lenient_entry_offset_past_eof_yields_empty_with_accurate_warning() {
        let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1, 2, 3, 4])], None);
        let rec = HEADER_SIZE as usize;
        // Point the payload entirely past EOF (offset and length both overrun).
        let past = blob.len() as u32 + 0x100;
        LittleEndian::write_u32(&mut blob[rec + 4..rec + 8], past);
        LittleEndian::write_u32(&mut blob[rec + 8..rec + 12], 4);
        let ftab = parse_ftab_from_bytes(&blob, ValidationMode { lenient: true }).unwrap();
        assert!(ftab.entries[0].data.is_empty());
        assert!(ftab.entries[0].truncated);
        assert_eq!(
            ftab.warnings
                .iter()
                .filter(|w| matches!(w, FtabWarning::TruncatedRead(_)))
                .count(),
            1
        );
        // The warning must not claim anything was "clamped" — nothing was readable.
        assert!(ftab
            .warnings
            .iter()
            .find(|w| matches!(w, FtabWarning::TruncatedRead(_)))
            .unwrap()
            .to_string()
            .contains("at or past file length"));
        assert!(!ftab
            .warnings
            .iter()
            .find(|w| matches!(w, FtabWarning::TruncatedRead(_)))
            .unwrap()
            .to_string()
            .contains("clamped"));
    }

    #[test]
    fn zero_length_manifest_is_none_even_with_offset() {
        for lenient in [false, true] {
            let mut blob = build_ftab(MAGIC_LOWER, &[(*b"rkos", vec![1])], None);
            // Non-zero offset but zero length must short-circuit to None.
            LittleEndian::write_u32(&mut blob[0x10..0x14], 0x30);
            LittleEndian::write_u32(&mut blob[0x14..0x18], 0);
            let ftab = parse_ftab_from_bytes(&blob, ValidationMode { lenient }).unwrap();
            assert!(ftab.manifest.is_none(), "lenient={lenient}");
        }
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
        assert!(ftab.manifest.unwrap().data.is_none());
        assert_eq!(
            ftab.warnings
                .iter()
                .filter(|w| matches!(w, FtabWarning::TruncatedRead(_)))
                .count(),
            1
        );
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
        assert_eq!(
            ftab.manifest.as_ref().and_then(|m| m.data.as_deref()),
            Some(&[0xAA, 0xBB][..])
        );
        assert_eq!(
            ftab.warnings
                .iter()
                .filter(|w| matches!(w, FtabWarning::TruncatedRead(_)))
                .count(),
            1
        );
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
