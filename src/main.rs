use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser};

mod rkos_parser;

use rkos_parser::ValidationMode;

/// Dump FTAB container payloads to an output directory.
#[derive(Parser, Debug)]
#[command(
    name = "ftab-dump",
    version,
    about = "FTAB container dumper (rkosftab/RKOSFTAB)"
)]
struct Cli {
    /// Path of the FTAB file to process
    #[arg(value_name = "FTAB_FILE", required = true)]
    ftab_file: PathBuf,

    /// Output directory (created if it does not exist)
    #[arg(
        short = 'o',
        long = "outdir",
        value_name = "DIR",
        default_value = "ftab_dump"
    )]
    outdir: PathBuf,

    /// Overwrite into an existing, non-empty directory without prompting
    #[arg(short = 'f', long = "force", action = ArgAction::SetTrue)]
    force: bool,

    /// Verbose: list tags and sizes as they are written
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    verbose: bool,

    /// Print the FTAB header, manifest, and file table without writing files
    #[arg(short = 'i', long = "info", action = ArgAction::SetTrue)]
    info: bool,

    /// Write zero-length placeholder entries as empty files
    #[arg(long = "keep-empty", action = ArgAction::SetTrue)]
    keep_empty: bool,

    /// Treat parser warnings as errors
    #[arg(long = "strict", action = ArgAction::SetTrue)]
    strict: bool,

    /// Dump the optional manifest ("ticket") block, if present, to 'manifest.bin'
    #[arg(long = "dump-manifest", action = ArgAction::SetTrue)]
    dump_manifest: bool,

    /// Reproduce the device's lenient reader: clamp out-of-bounds payloads and
    /// manifest to the bytes actually available (with warnings) instead of
    /// rejecting them. Mirrors `-[UARPRTKitFTAB getDataBlock:offset:]`.
    #[arg(long = "lenient", alias = "header-only", action = ArgAction::SetTrue)]
    lenient: bool,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // Read the entire file.
    let mut f = fs::File::open(&cli.ftab_file)
        .map_err(|e| format!("cannot open {}: {e}", cli.ftab_file.display()))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {}: {e}", cli.ftab_file.display()))?;

    // Parse & validate.
    let ftab = rkos_parser::parse_ftab_from_bytes(
        &bytes,
        ValidationMode {
            lenient: cli.lenient,
        },
    )
    .map_err(|e| format!("not a valid FTAB image: {e}"))?;

    // Surface non-fatal anomalies (clamped payloads/manifest in lenient mode).
    for w in &ftab.warnings {
        eprintln!("warning: {w}");
    }

    if cli.strict && !ftab.warnings.is_empty() {
        return Err(format!(
            "{} FTAB warning(s) treated as errors by --strict",
            ftab.warnings.len()
        )
        .into());
    }
    if cli.info {
        print_info(&ftab, bytes.len() as u64);
        return Ok(());
    }

    // Prepare the output directory.
    if cli.outdir.exists() {
        // A pre-existing non-directory can never receive our output, even with
        // --force, so reject it explicitly rather than failing later mid-write.
        if !cli.outdir.is_dir() {
            return Err(format!(
                "output path {} exists and is not a directory",
                cli.outdir.display()
            )
            .into());
        }
        if !cli.force && !is_empty_dir(&cli.outdir)? {
            return Err(format!(
                "directory {} exists and is not empty; pass '-f' to overwrite into it",
                cli.outdir.display()
            )
            .into());
        }
    } else {
        fs::create_dir_all(&cli.outdir)
            .map_err(|e| format!("cannot create {}: {e}", cli.outdir.display()))?;
    }

    // Dump the manifest if requested.
    if cli.dump_manifest {
        if let Some(m) = ftab.manifest.as_ref().and_then(|m| m.data.as_ref()) {
            let path = cli.outdir.join("manifest.bin");
            fs::write(&path, m).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
            if cli.verbose {
                println!("manifest.bin: {} bytes", m.len());
            }
        } else if cli.verbose {
            println!("(no manifest present)");
        }
    }

    // Dump the subfiles. Filenames are derived from the 4CC tag, sanitised
    // against path traversal, and disambiguated on collision.
    let mut used: HashSet<String> = HashSet::new();
    let mut total: u64 = 0;
    let mut written = 0;
    let mut skipped = 0;

    for entry in &ftab.entries {
        if entry.is_placeholder() && !cli.keep_empty {
            skipped += 1;
            continue;
        }
        let fname = make_unique_filename(&entry.tag, &mut used);
        let out = cli.outdir.join(&fname);
        fs::write(&out, &entry.data).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
        total += entry.data.len() as u64;
        written += 1;

        if cli.verbose {
            let note = if entry.truncated { " [TRUNCATED]" } else { "" };
            println!(
                "{} -> {}: {} bytes (offset=0x{:X}, declared_length={}){}",
                entry.tag_string(),
                fname,
                entry.data.len(),
                entry.offset,
                entry.length,
                note
            );
        }
    }

    println!("wrote {} files with a total of {} bytes", written, total);

    if skipped > 0 {
        println!("skipped {} zero-length placeholder(s)", skipped);
    }

    Ok(())
}

fn print_info(ftab: &rkos_parser::Ftab, file_len: u64) {
    let header = &ftab.header;

    println!("FTAB image: {} bytes", file_len);
    println!("Magic: {}", ftab.magic_variant.as_str());
    println!("Generation: {}", header.generation);
    println!("Valid: 0x{:08X}", header.valid_flag);
    println!("Boot nonce: 0x{:016X}", header.boot_nonce);
    println!(
        "File table: 0x{:X}..0x{:X} ({} entries, {} payloads, {} placeholders)",
        rkos_parser::HEADER_SIZE,
        ftab.file_table_end(),
        header.number_of_files,
        ftab.payload_count(),
        ftab.placeholder_count()
    );

    match &ftab.manifest {
        Some(m) => println!(
            "Manifest: offset=0x{:X}, length={}, placement={}",
            m.offset,
            m.length,
            m.placement.as_str()
        ),
        None => println!("Manifest: none"),
    }

    if let Some((lo, hi)) = ftab.payload_span() {
        println!("Payload span: 0x{:X}..0x{:X}", lo, hi);
    }
    println!("Payload bytes: {}", ftab.payload_bytes());
    println!();
    println!(
        "{:<4} {:>4} {:>10} {:>10} {:>10}  NOTE",
        "TAG", "#", "OFFSET", "LENGTH", "END"
    );

    for (idx, entry) in ftab.entries.iter().enumerate() {
        let mut notes = Vec::new();
        if entry.is_placeholder() {
            notes.push("placeholder");
        }
        if entry.truncated {
            notes.push("truncated");
        }
        if entry.offset % 4 != 0 && !entry.is_placeholder() {
            notes.push("misaligned");
        }
        if let Some(m) = &ftab.manifest {
            if !entry.is_placeholder()
                && (entry.offset as u64) < m.end_offset()
                && (m.offset as u64) < entry.end_offset()
            {
                notes.push("overlaps manifest");
            }
        }

        println!(
            "{:<4} {:>4} 0x{:08X} {:>10} 0x{:08X}  {}",
            entry.tag_string(),
            idx,
            entry.offset,
            entry.length,
            entry.end_offset(),
            notes.join(", ")
        );
    }

    if !ftab.warnings.is_empty() {
        println!();
        println!("Warnings: {}", ftab.warnings.len());
    }
}

fn is_empty_dir(p: &Path) -> std::io::Result<bool> {
    if !p.is_dir() {
        return Ok(false);
    }
    Ok(fs::read_dir(p)?.next().is_none())
}

/// Returns `true` for bytes that may appear in a path component: a conservative
/// allowlist of ASCII alphanumerics and a few benign punctuation marks. This
/// excludes `/` and `\\` (so a tag can never introduce a directory separator);
/// whole-name portability (aliases, reserved names, trailing dots) is enforced
/// separately by [`is_portable_basename`].
fn is_safe_filename_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'.')
}

/// Names reserved by Windows for DOS devices, which cannot back a regular file
/// (case-insensitive, with or without an extension).
const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Returns `true` if `s` is safe to use verbatim as a single path component on
/// every platform we build for (Linux, macOS, Windows). Rejects the directory
/// aliases `.`/`..`, names Windows silently rewrites (a trailing `.` or space),
/// and Windows reserved device names — all of which would make the on-disk name
/// differ from, or fail to match, what the tool reports.
fn is_portable_basename(s: &str) -> bool {
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    if s.ends_with('.') || s.ends_with(' ') {
        return false;
    }
    let stem = s.split('.').next().unwrap_or(s);
    !WINDOWS_RESERVED
        .iter()
        .any(|r| r.eq_ignore_ascii_case(stem))
}

/// Builds the base filename for a tag: the literal 4CC if every byte is safe and
/// the whole name is portable, otherwise an 8-hex-digit form.
fn base_name_for_tag(tag: &[u8; 4]) -> String {
    if tag.iter().all(|&b| is_safe_filename_byte(b)) {
        // Every byte is ASCII, so this is a lossless conversion.
        let s: String = tag.iter().map(|&b| b as char).collect();
        if is_portable_basename(&s) {
            return s;
        }
    }
    hex_name(tag)
}

fn hex_name(tag: &[u8; 4]) -> String {
    format!("{:02X}{:02X}{:02X}{:02X}", tag[0], tag[1], tag[2], tag[3])
}

/// Produces a collision-free filename for `tag`, recording it in `used`.
fn make_unique_filename(tag: &[u8; 4], used: &mut HashSet<String>) -> String {
    let base = base_name_for_tag(tag);
    if used.insert(base.clone()) {
        return base;
    }
    let mut n: u32 = 1;
    loop {
        let cand = format!("{base}_{n}");
        if used.insert(cand.clone()) {
            return cand;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_separators_in_tag() {
        // A tag containing '/' must never produce a path component with '/'.
        assert_eq!(base_name_for_tag(b"a/b\\"), "612F625C");
        assert!(!base_name_for_tag(b"a/b\\").contains('/'));
        assert!(!base_name_for_tag(b"a/b\\").contains('\\'));
    }

    #[test]
    fn rejects_dot_aliases() {
        // 0x2E is '.', which is a safe byte, but "." / ".." must not be used.
        // Pad with NUL (unsafe) so the result is the hex form rather than a
        // four-dot name; the key property is that no directory alias leaks.
        let n = base_name_for_tag(b"..\0\0");
        assert_ne!(n, ".");
        assert_ne!(n, "..");
    }

    #[test]
    fn trailing_dot_tag_falls_back_to_hex() {
        // Windows silently strips trailing dots, so "abc." and "...." (which
        // would normalize away entirely) must not be used verbatim.
        assert_eq!(base_name_for_tag(b"abc."), "6162632E");
        assert_eq!(base_name_for_tag(b"...."), "2E2E2E2E");
    }

    #[test]
    fn windows_reserved_names_fall_back_to_hex() {
        // "com1"/"lpt1" etc. cannot back a regular file on Windows.
        assert_eq!(base_name_for_tag(b"com1"), "636F6D31");
        assert_eq!(base_name_for_tag(b"COM9"), "434F4D39");
        assert_eq!(base_name_for_tag(b"lpt1"), "6C707431");
        // "com0"/"coms" are NOT reserved and remain literal.
        assert_eq!(base_name_for_tag(b"com0"), "com0");
        assert_eq!(base_name_for_tag(b"coms"), "coms");
    }

    #[test]
    fn non_printable_tag_becomes_hex() {
        assert_eq!(base_name_for_tag(&[0x00, 0x01, 0xFF, 0x7F]), "0001FF7F");
    }

    #[test]
    fn plain_tag_is_preserved() {
        assert_eq!(base_name_for_tag(b"rkos"), "rkos");
        assert_eq!(base_name_for_tag(b"fw01"), "fw01");
        assert_eq!(base_name_for_tag(b"a-b+"), "a-b+");
    }

    #[test]
    fn collisions_are_disambiguated() {
        let mut used = HashSet::new();
        assert_eq!(make_unique_filename(b"rkos", &mut used), "rkos");
        assert_eq!(make_unique_filename(b"rkos", &mut used), "rkos_1");
        assert_eq!(make_unique_filename(b"rkos", &mut used), "rkos_2");
        // A distinct tag is untouched.
        assert_eq!(make_unique_filename(b"prms", &mut used), "prms");
    }
}
