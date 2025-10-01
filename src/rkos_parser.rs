use std::cmp::Ordering;
use byteorder::{ReadBytesExt, LittleEndian, BigEndian};

#[inline]
fn read_vec<R>(file: &mut R, len: usize) -> Result<Vec<u8>, std::io::Error>
    where R: std::io::Read,
{
    let mut buf = [0u8].repeat(len);

    file.read(&mut *buf)?;

    Ok(buf)
}

#[inline]
fn cmp_str(buf: &Vec<u8>, sstr: &[u8]) -> bool {
    buf.cmp(&sstr.to_vec()) == Ordering::Equal
}

pub struct FtabEntry {
    pub tag: String,
    pub data: Vec<u8>,
}

pub struct Ftab {
    pub tag: String,
    pub magic: String,
    pub entries: Vec<FtabEntry>,
}

pub fn parse_ftab<R>(src: &mut R) -> std::io::Result<Ftab>
    where R: std::io::Read,
{
    src.read_u16::<BigEndian>()?;    // 00 20
    src.read_u16::<BigEndian>()?;    // 00 02

    src.read_u32::<LittleEndian>()?; // FF FF FF FF
    src.read_u32::<LittleEndian>()?; // 00 00 00 00
    src.read_u32::<LittleEndian>()?; // 00 00 00 00

    let ticket_offset = src.read_u32::<LittleEndian>()?;
    let ticket_size = src.read_u32::<LittleEndian>()?;

    src.read_u32::<LittleEndian>()?; // 00 00 00 00
    src.read_u32::<LittleEndian>()?; // 00 00 00 00

    let fw_tag =
        read_vec(src, 4)?; // r  k  o  s (??)

    let fw_magic =
        read_vec(src, 4)?; // f  t  a  b

    if !cmp_str(&fw_tag, b"rkos") {
        println!(
            "{}",
            [
                "",
                "Error: the file provided does not include the tag 'rkos'.",
                "",
                "Of course it is possible that you are dealing with an ftab",
                "file that has a different tag, but honestly, it's probably",
                "unlikely. Either way, proceeding... good luck.",
                "",
            ].join("\n"),
        );
    }

    assert!(
        cmp_str(&fw_magic, b"ftab"),
        "Firmware magic could not be found. (expected 'ftab' at offset 0x20)",
    );

    let mut ftab = Ftab {
        tag: String::from_utf8_lossy(&fw_tag).to_string(),
        magic: String::from_utf8_lossy(&fw_magic).to_string(),
        entries: Vec::new(),
    };

    let fw_num_entries =
        src.read_u32::<LittleEndian>()?;   // 00 00 00 00

    src.read_u32::<LittleEndian>()?; // 00 00 00 00

    let mut entries: Vec<(String, u32, u32)> = Vec::new();

    for i in 0..fw_num_entries as usize {
        let entry = (
            String::from_utf8_lossy(&read_vec(src, 4)?).to_string(),
            src.read_u32::<LittleEndian>()?,
            src.read_u32::<LittleEndian>()?,
        );

        // pad
        src.read_u32::<LittleEndian>()?;

        if entry.2 <= 0 { // occurs on AirPods Pro 3 firmware
            continue;
        }

        entries.push(entry.clone());

        if i != 0 {
            let prev_entry = &entries.get(i - 1usize).unwrap();
            let size = prev_entry.2 as i64;
            let delta: i64 = entry.1 as i64 - prev_entry.1 as i64;

            assert!(
                (delta - size) < 4,
                "Error: offset not within alignment of 4 bytes",
            );
        }
    }

    // for some reason this is included
    // in the header of the file;
    // presumably as a basic sanity
    // check that all data was received
    entries.push(
        (
            "ticket".to_string(),
            ticket_offset,
            ticket_size,
        ),
    );

    for entry in entries.iter() {
        ftab.entries.push(
            FtabEntry {
                tag: entry.0.clone(),
                data: read_vec(src, entry.2 as usize)?,
            }
        );

        let size_align_mod = entry.2 % 4;

        // skip alignment bytes
        if size_align_mod != 0 {
            read_vec(
                src,
                4usize - size_align_mod as usize,
            )?;
        };
    }

    Ok(ftab)
}
