//! FTAB container parser (rksoftab/RKSOFTAB).
//!
//! This implements the layout validated by the decompiled routines:
//! - Header: 48 bytes (0x30)
//! - Magic (0x20..0x28): "rksoftab" or "RKSOFTAB"
//! - Metadata table: N * 16 bytes immediately after header
//! - Each entry: [4CC tag][u32 offset][u32 length][u32 reserved]
//! - Payloads at absolute offsets; offsets must be >= table_end, and offset+length within file.
//! - Manifest (optional): header fields (offset,len); if len>0 must be within file.
//!
//! Field endianness: header & entries are little-endian; TLV inside manifest is network order,
//! but the manifest is treated as opaque here.

use byteorder::{ByteOrder, LittleEndian};
use std::fmt;

#[derive(Clone, Copy)]
pub struct ValidationMode {
    pub header_only: bool,
}

#[derive(Debug)]
pub struct FtabEntry {
    pub tag: [u8; 4],
    pub offset: u32,
    pub length: u32,
    pub data: Vec<u8>,
}

impl FtabEntry {
    pub fn tag_string(&self) -> String {
        let printable = self.tag.iter().all(|b| (0x20..=0x7E).contains(b));

        if printable {
            String::from_utf8_lossy(&self.tag).to_string()
        } else {
            format!("{:02X}{:02X}{:02X}{:02X}", self.tag[0], self.tag[1], self.tag[2], self.tag[3])
        }
    }
}

pub struct Ftab {
    pub generation: u32,
    pub valid_flag: u32,
    pub boot_nonce: u64,
    pub magic: [u8; 8], // "rksoftab" | "RKSOFTAB"
    pub number_of_files: u32,
    pub manifest: Option<Vec<u8>>,
    pub entries: Vec<FtabEntry>,
}

impl fmt::Debug for Ftab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ftab")
            .field("generation", &self.generation)
            .field("valid_flag", &self.valid_flag)
            .field("boot_nonce", &self.boot_nonce)
            .field("magic", &String::from_utf8_lossy(&self.magic))
            .field("number_of_files", &self.number_of_files)
            .field("manifest_len", &self.manifest.as_ref().map(|m| m.len()))
            .field("entries", &self.entries.len())
            .finish()
    }
}

#[derive(Debug)]
pub enum FtabError {
    Truncated(&'static str),
    InvalidMagic([u8; 8]),
    InvalidFileCount(u32),
    TableOutOfBounds { table_end: u64, file_len: u64 },
    ManifestOutOfBounds { off: u64, len: u64, file_len: u64 },
    EntryOutOfBounds { idx: usize, off: u64, len: u64, file_len: u64 },
    EntryBeforeTable { idx: usize, off: u64, table_end: u64 },
}

impl std::error::Error for FtabError {}
impl fmt::Display for FtabError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use FtabError::*;

        match self {
            Truncated(what) =>
                write!(f, "truncated {}", what),
            InvalidMagic(m) =>
                write!(f, "invalid magic at 0x20: {:?}", String::from_utf8_lossy(m)),
            InvalidFileCount(n) =>
                write!(f, "invalid number_of_files: {} (expected 1..=127)", n),
            TableOutOfBounds { table_end, file_len } =>
                write!(f, "metadata table end (0x{:X}) > file length (0x{:X})", table_end, file_len),
            ManifestOutOfBounds { off, len, file_len } =>
                write!(f, "manifest [{}..{}] exceeds file length 0x{:X}",
                       off, off.saturating_add(*len), file_len),
            EntryOutOfBounds { idx, off, len, file_len } =>
                write!(f, "entry #{} [{}..{}] exceeds file length 0x{:X}",
                       idx, off, off.saturating_add(*len), file_len),
            EntryBeforeTable { idx, off, table_end } =>
                write!(f, "entry #{} offset 0x{:X} is before table_end 0x{:X}", idx, off, table_end),
        }
    }
}

/// Parse an FTAB image from the complete file bytes, with strict checks
/// matching `ACFUFTABFile::isValidFileData` and `-[FTABFileOS parseFileData]`.
pub fn parse_ftab_from_bytes(bytes: &[u8], mode: ValidationMode) -> Result<Ftab, FtabError> {
    // Header must be at least 48 bytes
    if bytes.len() < 0x30 {
        return Err(FtabError::Truncated("header (need 48 bytes)"));
    }

    // Header fields (little-endian)
    let generation = LittleEndian::read_u32(&bytes[0x00..0x04]);
    let valid_flag = LittleEndian::read_u32(&bytes[0x04..0x08]);
    let boot_nonce = LittleEndian::read_u64(&bytes[0x08..0x10]);

    let manifest_offset = LittleEndian::read_u32(&bytes[0x10..0x14]) as u64;
    let manifest_length = LittleEndian::read_u32(&bytes[0x14..0x18]) as u64;

    // 0x18..0x20 reserved (u64)

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&bytes[0x20..0x28]);

    let number_of_files = LittleEndian::read_u32(&bytes[0x28..0x2C]);

    // 0x2C..0x30 reserved (u32)

    // Magic check (byte-wise)
    if &magic != b"rksoftab"
    && &magic != b"RKSOFTAB"
    && &magic != b"rkosftab"
    && &magic != b"RKOSFTAB" {
        return Err(FtabError::InvalidMagic(magic));
    }

    // number_of_files: 1..=127
    if number_of_files == 0 || number_of_files >= 128 {
        return Err(FtabError::InvalidFileCount(number_of_files));
    }

    // Metadata table bounds: starts at 0x30, length N*16
    let table_start = 0x30u64;
    let table_len = (number_of_files as u64) * 16;
    let table_end = table_start + table_len;

    let file_len = bytes.len() as u64;

    if table_end > file_len {
        return Err(FtabError::TableOutOfBounds { table_end, file_len });
    }

    // Manifest (optional)
    let manifest = if manifest_length > 0 {
        let end = manifest_offset.saturating_add(manifest_length);

        if !mode.header_only {
            if end > file_len {
                return Err(FtabError::ManifestOutOfBounds {
                    off: manifest_offset, len: manifest_length, file_len,
                });
            }
        }

        if (manifest_offset as usize) <= bytes.len() && (end as usize) <= bytes.len() {
            Some(bytes[manifest_offset as usize .. end as usize].to_vec())
        } else {
            // In header-only mode accept leaving it None (mirrors relaxed behavior)
            None
        }
    } else {
        None
    };

    // Parse entries
    let mut entries = Vec::with_capacity(number_of_files as usize);

    for i in 0..(number_of_files as usize) {
        let off = (table_start as usize) + i * 16;
        let tag = <[u8; 4]>::try_from(&bytes[off .. off + 4]).unwrap();

        let payload_off = LittleEndian::read_u32(&bytes[off + 4 .. off + 8]) as u64;
        let payload_len = LittleEndian::read_u32(&bytes[off + 8 .. off + 12]) as u64;

        // off+12..+16 reserved

        // Skip zero-length entries, as they are valid placeholders.
        if payload_len == 0 {
            continue;
        }

        // Each payload must start at or after the table end
        if payload_off < table_end {
            return Err(FtabError::EntryBeforeTable {
                idx: i, off: payload_off, table_end,
            });
        }

        // In full validation, enforce end ≤ file_len
        let end = payload_off.saturating_add(payload_len);

        if !mode.header_only {
            if end > file_len {
                return Err(FtabError::EntryOutOfBounds {
                    idx: i, off: payload_off, len: payload_len, file_len,
                });
            }
        }

        // Slice data if in range; otherwise empty (header-only permissiveness)
        let data = if (payload_off as usize) <= bytes.len() && (end as usize) <= bytes.len() {
            bytes[payload_off as usize .. end as usize].to_vec()
        } else {
            Vec::new()
        };

        entries.push(FtabEntry {
            tag,
            offset: payload_off as u32,
            length: payload_len as u32,
            data,
        });
    }

    Ok(Ftab {
        generation,
        valid_flag,
        boot_nonce,
        magic,
        number_of_files,
        manifest,
        entries,
    })
}
