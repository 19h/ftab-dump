use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use clap::{ArgAction, Parser};

mod rkos_parser;

/// Dump FTAB container payloads to an output directory.
#[derive(Parser, Debug)]
#[command(name = "ftab-dump", version = "1.0.4-alpha.1")]
#[command(about = "FTAB container dumper (rksoftab/RKSOFTAB) with strict validation")]
struct Cli {
    /// Path of the FTAB file to process
    #[arg(value_name = "FTAB_FILE", required = true)]
    ftab_file: PathBuf,

    /// Output directory (created if not exists)
    #[arg(short = 'o', long = "outdir", value_name = "DIR", default_value = "ftab_dump")]
    outdir: PathBuf,

    /// Overwrite into an existing directory without prompting
    #[arg(short = 'f', long = "force", action = ArgAction::SetTrue)]
    force: bool,

    /// Verbose: list tags and sizes as they are written
    #[arg(short = 'v', long = "verbose", action = ArgAction::SetTrue)]
    verbose: bool,

    /// Dump the optional manifest block (if present) to 'manifest.bin'
    #[arg(long = "dump-manifest", action = ArgAction::SetTrue)]
    dump_manifest: bool,

    /// Relax validation to header-only checks (do not verify payload end ≤ file size).
    /// This exists only to reproduce 'headerOnly' mode in ACFUFTABFile::isValidFileData(..., true).
    #[arg(long = "header-only", action = ArgAction::SetTrue)]
    header_only: bool,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    // Read entire file
    let mut f = fs::File::open(&cli.ftab_file)?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;

    // Parse & validate
    let ftab = rkos_parser::parse_ftab_from_bytes(&bytes, rkos_parser::ValidationMode {
        header_only: cli.header_only,
    }).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Prepare output dir
    if cli.outdir.exists() {
        if !cli.force && !is_empty_dir(&cli.outdir)? {
            eprintln!(
                "Error: directory {:?} exists and is not empty. Pass '-f' to proceed.",
                &cli.outdir
            );
            return Ok(());
        }
    } else {
        fs::create_dir_all(&cli.outdir)?;
    }

    // Dump manifest if requested
    if cli.dump_manifest {
        if let Some(m) = &ftab.manifest {
            let path = cli.outdir.join("manifest.bin");
            fs::write(&path, m)?;
            if cli.verbose {
                println!("manifest.bin: {} bytes", m.len());
            }
        }
    }

    // Dump subfiles
    let mut total: u64 = 0;
    for (idx, entry) in ftab.entries.iter().enumerate() {
        let fname = safe_tag_filename(&entry.tag, idx);
        let out = cli.outdir.join(fname);
        fs::write(&out, &entry.data)?;
        total += entry.data.len() as u64;

        if cli.verbose {
            println!("{}: {} bytes (offset={}, length={})",
                     entry.tag_string(),
                     entry.data.len(),
                     entry.offset,
                     entry.length);
        }
    }

    println!("✔ wrote {} files with total of {} bytes",
             ftab.entries.len(),
             total);

    Ok(())
}

fn is_empty_dir(p: &Path) -> io::Result<bool> {
    if !p.is_dir() { return Ok(false); }
    for e in fs::read_dir(p)? {
        let _ = e?;
        return Ok(false);
    }
    Ok(true)
}

fn safe_tag_filename(tag4: &[u8; 4], index: usize) -> String {
    // Prefer ASCII filename from 4CC tag; fall back to hex if non-printable.
    let ascii_ok = tag4.iter().all(|b| (0x20..=0x7E).contains(b));
    if ascii_ok {
        // Avoid collisions by suffixing index only when duplicates occur.
        if index == 0 {
            String::from_utf8_lossy(tag4).to_string()
        } else {
            format!("{}_{index}",
                    String::from_utf8_lossy(tag4))
        }
    } else {
        if index == 0 {
            format!("{:02X}{:02X}{:02X}{:02X}", tag4[0], tag4[1], tag4[2], tag4[3])
        } else {
            format!("{:02X}{:02X}{:02X}{:02X}_{index}",
                    tag4[0], tag4[1], tag4[2], tag4[3])
        }
    }
}
