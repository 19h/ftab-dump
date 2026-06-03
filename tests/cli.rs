//! End-to-end tests driving the compiled `ftab-dump` binary.
//!
//! These exercise the externally observable contract — exit codes, the files
//! written to the output directory, path-traversal containment, and the
//! strict/lenient bounds behaviour — against synthetic FTAB images built in
//! memory. They use only `std`, invoking the binary via `CARGO_BIN_EXE_*`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const HEADER_SIZE: usize = 0x30;
const ENTRY_SIZE: usize = 16;

/// Build a synthetic FTAB image. Payloads are laid out contiguously after the
/// metadata table (and the optional manifest). `count_override` lets a test
/// declare a `number_of_files` that disagrees with the actual entry list, and
/// `truncate_to` lets a test cut the buffer short to simulate corruption.
fn build_ftab(
    magic: &[u8; 8],
    entries: &[([u8; 4], Vec<u8>)],
    manifest: Option<&[u8]>,
    count_override: Option<u32>,
    truncate_to: Option<usize>,
) -> Vec<u8> {
    let n = entries.len();
    let table_end = HEADER_SIZE + n * ENTRY_SIZE;

    let mut blob = vec![0u8; HEADER_SIZE];
    blob[0x20..0x28].copy_from_slice(magic);
    let count = count_override.unwrap_or(n as u32);
    blob[0x28..0x2C].copy_from_slice(&count.to_le_bytes());

    // Reserve the table region.
    blob.resize(table_end, 0);

    let mut cursor = table_end as u32;
    if let Some(m) = manifest {
        let off = cursor;
        blob.extend_from_slice(m);
        cursor += m.len() as u32;
        blob[0x10..0x14].copy_from_slice(&off.to_le_bytes());
        blob[0x14..0x18].copy_from_slice(&(m.len() as u32).to_le_bytes());
    }

    for (i, (tag, data)) in entries.iter().enumerate() {
        let off = cursor;
        let rec = HEADER_SIZE + i * ENTRY_SIZE;
        blob[rec..rec + 4].copy_from_slice(tag);
        blob[rec + 4..rec + 8].copy_from_slice(&off.to_le_bytes());
        blob[rec + 8..rec + 12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        blob.extend_from_slice(data);
        cursor += data.len() as u32;
    }

    if let Some(t) = truncate_to {
        blob.truncate(t);
    }
    blob
}

/// A unique, freshly-created scratch directory for one test, removed on drop.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ftab-dump-it-{}-{}-{}",
            std::process::id(),
            label,
            n
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write_input(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ftab-dump"))
        .args(args)
        .output()
        .expect("failed to spawn ftab-dump")
}

fn osv<'a>(items: &'a [&'a Path]) -> Vec<&'a std::ffi::OsStr> {
    items.iter().map(|p| p.as_os_str()).collect()
}

#[test]
fn extracts_basic_image() {
    let s = Scratch::new("basic");
    let blob = build_ftab(
        b"rkosftab",
        &[(*b"rkos", b"ABCDEFGH".to_vec()), (*b"prms", vec![0u8; 12])],
        Some(b"TICKET"),
        None,
        None,
    );
    let input = s.write_input("ftab.bin", &blob);
    let out = s.path("out");

    let o = run(&osv(&[
        &input,
        Path::new("-o"),
        &out,
        Path::new("--dump-manifest"),
    ]));
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(std::fs::read(out.join("rkos")).unwrap(), b"ABCDEFGH");
    assert_eq!(std::fs::read(out.join("prms")).unwrap(), vec![0u8; 12]);
    assert_eq!(std::fs::read(out.join("manifest.bin")).unwrap(), b"TICKET");
}

#[test]
fn rejects_transposed_magic() {
    let s = Scratch::new("badmagic");
    // "rksoftab" is the historical typo and must be rejected.
    let blob = build_ftab(b"rksoftab", &[(*b"rkos", b"X".to_vec())], None, None, None);
    let input = s.write_input("ftab.bin", &blob);
    let out = s.path("out");
    let o = run(&osv(&[&input, Path::new("-o"), &out]));
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("invalid magic"), "stderr: {err}");
    assert!(
        !out.exists(),
        "output dir must not be created on parse failure"
    );
}

#[test]
fn path_traversal_is_contained() {
    let s = Scratch::new("traversal");
    // Tags that, used verbatim, would escape the output directory.
    let blob = build_ftab(
        b"rkosftab",
        &[(*b"../x", b"PWN".to_vec()), (*b"a/b\\", b"NOPE".to_vec())],
        None,
        None,
        None,
    );
    let input = s.write_input("ftab.bin", &blob);
    let out = s.path("out");
    let o = run(&osv(&[&input, Path::new("-o"), &out]));
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );

    // Both tags must collapse to safe hex names inside `out`, and nothing may
    // appear outside it.
    let escaped = s.dir.join("x");
    assert!(!escaped.exists(), "payload escaped the output directory");
    let names: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "names: {names:?}");
    for name in &names {
        assert!(!name.contains('/') && !name.contains('\\') && name != "." && name != "..");
    }
}

#[test]
fn strict_rejects_truncated_payload_lenient_clamps() {
    let s = Scratch::new("bounds");
    // Declare a 4-byte payload but cut the file so only 2 bytes remain.
    let mut blob = build_ftab(
        b"rkosftab",
        &[(*b"rkos", b"ABCD".to_vec())],
        None,
        None,
        None,
    );
    blob.truncate(blob.len() - 2); // payload now 2 of declared 4 bytes
    let input = s.write_input("ftab.bin", &blob);

    // Strict (default): hard error, nothing written.
    let out_strict = s.path("strict");
    let o = run(&osv(&[&input, Path::new("-o"), &out_strict]));
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("exceeds file length"));

    // Lenient: clamps to the available bytes, warns, exits 0.
    let out_lenient = s.path("lenient");
    let o = run(&osv(&[
        &input,
        Path::new("-o"),
        &out_lenient,
        Path::new("--lenient"),
    ]));
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("clamped"));
    assert_eq!(std::fs::read(out_lenient.join("rkos")).unwrap(), b"AB");
}

#[test]
fn header_only_is_a_lenient_alias() {
    let s = Scratch::new("alias");
    let mut blob = build_ftab(
        b"rkosftab",
        &[(*b"rkos", b"ABCD".to_vec())],
        None,
        None,
        None,
    );
    blob.truncate(blob.len() - 2);
    let input = s.write_input("ftab.bin", &blob);
    let out = s.path("out");
    let o = run(&osv(&[
        &input,
        Path::new("-o"),
        &out,
        Path::new("--header-only"),
    ]));
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(std::fs::read(out.join("rkos")).unwrap(), b"AB");
}

#[test]
fn duplicate_tags_are_disambiguated() {
    let s = Scratch::new("dups");
    let blob = build_ftab(
        b"rkosftab",
        &[
            (*b"dup1", b"AA".to_vec()),
            (*b"dup1", b"BB".to_vec()),
            (*b"dup1", b"CC".to_vec()),
        ],
        None,
        None,
        None,
    );
    let input = s.write_input("ftab.bin", &blob);
    let out = s.path("out");
    let o = run(&osv(&[&input, Path::new("-o"), &out]));
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(std::fs::read(out.join("dup1")).unwrap(), b"AA");
    assert_eq!(std::fs::read(out.join("dup1_1")).unwrap(), b"BB");
    assert_eq!(std::fs::read(out.join("dup1_2")).unwrap(), b"CC");
}

#[test]
fn refuses_nonempty_dir_without_force() {
    let s = Scratch::new("nonempty");
    let blob = build_ftab(b"rkosftab", &[(*b"rkos", b"AB".to_vec())], None, None, None);
    let input = s.write_input("ftab.bin", &blob);
    let out = s.path("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("preexisting"), b"keep").unwrap();

    // Without -f: refuse with a non-zero exit, leaving the dir untouched.
    let o = run(&osv(&[&input, Path::new("-o"), &out]));
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not empty"));
    assert!(out.join("preexisting").exists());

    // With -f: succeed.
    let o = run(&osv(&[&input, Path::new("-o"), &out, Path::new("-f")]));
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(std::fs::read(out.join("rkos")).unwrap(), b"AB");
}

#[test]
fn high_file_count_is_accepted() {
    let s = Scratch::new("highcount");
    // 150 single-byte entries: above the removed 1..=127 cap.
    let entries: Vec<([u8; 4], Vec<u8>)> = (0..150u32)
        .map(|i| (*b"blob", vec![(i & 0xFF) as u8]))
        .collect();
    let blob = build_ftab(b"RKOSFTAB", &entries, None, None, None);
    let input = s.write_input("ftab.bin", &blob);
    let out = s.path("out");
    let o = run(&osv(&[&input, Path::new("-o"), &out]));
    assert!(
        o.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    // All collapse to the same tag, so 150 disambiguated files.
    let count = std::fs::read_dir(&out).unwrap().count();
    assert_eq!(count, 150);
}
