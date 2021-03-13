mod dynamic;
mod error;
mod file;
mod interpret;
mod notes;
mod program;
mod reader;
mod relocs;
mod section;
mod symbols;
mod version;
mod elf;

use std::path::PathBuf;
use structopt::StructOpt;
use anyhow::Result;
use elf::Elf;

#[derive(Debug, StructOpt)]
struct DisplayOptions {
    #[structopt(
        short = "a",
        long = "all",
        help = "Equivalent to: -h -l -S -s -d -V -i"
    )]
    all: bool,

    #[structopt(
        short = "h",
        long = "file-header",
        help = "Display the ELF file header"
    )]
    file_header: bool,

    #[structopt(
        short = "l",
        long = "program-headers",
        help = "Display the sections' header"
    )]
    program_headers: bool,

    #[structopt(
        short = "S",
        long = "section-headers",
        help = "Display the section headers"
    )]
    section_headers: bool,

    #[structopt(short = "s", long = "symbols", help = "Display the symbol table")]
    symbols: bool,

    #[structopt(long = "notes", help = "Display notes")]
    notes: bool,

    #[structopt(short = "d", long = "dynamic", help = "Display the dynamic section")]
    dynamic: bool,

    #[structopt(
        short = "V",
        long = "version-info",
        help = "Display the version sections"
    )]
    version_info: bool,

    #[structopt(
        short = "i",
        long = "interpret",
        help = "Display data of .interp section"
    )]
    interpret: bool,

    #[structopt(short = "r", long = "relocs", help = "Display the relocations")]
    relocs: bool,

    #[structopt(parse(from_os_str))]
    file: PathBuf,
}



fn main() -> Result<()> {

    let options = DisplayOptions::from_args();
    let elf = Elf::new(options.file)?;

    if options.file_header || options.all {
        elf.show_file_header()?;
    }

    if options.program_headers || options.all {
        elf.show_program_headers()?;
    }

    if options.section_headers || options.all {
        elf.show_section_headers()?;
    }

    if options.interpret || options.all {
        elf.show_interpret()?;
    }

    if options.symbols || options.all {
        elf.show_symbols()?;
    }

    if options.dynamic || options.all {
        elf.show_dynamic()?;
    }

    if options.notes || options.all {
        elf.show_notes()?;
    }

    if options.version_info || options.all {
        elf.show_version_info()?;
    }

    if options.relocs || options.all {
        elf.show_relocs()?;
    }

    Ok(())
}
