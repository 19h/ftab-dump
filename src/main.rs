use std::path::Path;

extern crate clap;
use clap::{Arg, App};

mod rkos_parser;

fn main() -> std::io::Result<()> {
    let matches = App::new("ftab-dump")
        .version("1.0.0")
        .author("Kenan Sulayman <kenan@sig.dev>")
        .about("The best ftab dumper in town!")
        .arg(Arg::with_name("DIR")
            .short("o")
            .long("outdir")
            .value_name("DIR")
            .help("Output directory")
            .takes_value(true)
            .default_value("ftab_dump"))
        .arg(Arg::with_name("FTAB_FILE")
            .help("Path of the ftab file to process")
            .required(true)
            .index(1))
        .arg(Arg::with_name("verbose")
            .short("v")
            .multiple(true)
            .help("Lists tags of dumped entries and the size of their data"))
        .arg(Arg::with_name("force")
            .short("f")
            .help("Ignore existing directory and write into it."))
        .get_matches();

    let fw_path = matches.value_of("FTAB_FILE").unwrap();
    let outdir = Path::new(matches.value_of("DIR").unwrap());

    let force = matches.is_present("force");
    let verbose = matches.is_present("verbose");

    let created_dir = std::fs::create_dir(outdir);

    if !force && !created_dir.is_ok() {
        println!(
            "Error: directory {:?} exists. Pass '-f' if you want to proceed anyway.",
            outdir,
        );

        return Ok(());
    }

    let mut fw_buf = match std::fs::File::open(fw_path) {
        Ok(buf) => buf,
        Err(err) => {
            println!("Error: {}.", err);

            return Ok(());
        }
    };

    let ftab = rkos_parser::parse_ftab(&mut fw_buf)?;

    let mut total_bytes = 0;
    let num_files = ftab.entries.len();

    for entry in ftab.entries {
        if verbose {
            println!("{}: {} bytes", entry.tag, entry.data.len());
        }

        total_bytes += entry.data.len();

        std::fs::write(
            outdir.join(entry.tag),
            &entry.data,
        )?;
    }

    println!(
        "✔ wrote {} files with total of {} bytes",
        num_files,
        total_bytes,
    );

    return Ok(());
}
