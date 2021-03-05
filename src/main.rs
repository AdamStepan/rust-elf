mod dynamic;
mod file;
mod interpret;
mod notes;
mod program;
mod reader;
mod relocs;
mod section;
mod symbols;
mod version;

use crate::dynamic::DynamicSection;
use crate::file::{ElfFileHeader, FileClass};
use crate::interpret::Interpret;
use crate::notes::NoteSections;
use crate::program::ProgramHeaders;
use crate::reader::Cursor;
use crate::relocs::RelocationSections;
use crate::section::SectionHeaders;
use crate::symbols::SymbolTables;
use crate::version::VersionSection;
use std::io::Read;
use std::path::PathBuf;
use structopt::StructOpt;

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

fn main() {
    use std::fs::File;

    let display = DisplayOptions::from_args();

    let mut file = File::open(display.file).unwrap();
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).unwrap();

    let mut reader = Cursor::new(buffer);

    let fh = ElfFileHeader::new(&mut reader);
    let ph = ProgramHeaders::new(&fh, &mut reader);
    let sh = SectionHeaders::new(&fh, &mut reader);

    if display.file_header || display.all {
        println!("{}", fh);
    }

    if display.program_headers || display.all {
        println!("{}", ph);
    }

    if display.section_headers || display.all {
        println!("{}", sh);
    }

    if display.interpret || display.all {
        println!("{}", Interpret::new(&ph, &mut reader));
    }

    if display.symbols || display.all {
        println!("{}", SymbolTables::new(&sh, &mut reader));
    }

    if display.notes || display.all {
        let addrsize = match fh.e_class {
            FileClass::ElfClass64 => 8,
            FileClass::ElfClass32 => 4,
            _ => panic!("Unable to determine elf file class"),
        };
        println!("{}", NoteSections::new(addrsize, &sh, &ph, &mut reader));
    }

    if display.dynamic || display.all {
        if let Some(dynamic) = DynamicSection::new(&sh, &mut reader) {
            println!("{}", dynamic);
        } else {
            println!("There is no dynamic section in this file\n");
        }
    }

    if display.version_info || display.all {
        if let Some(version_info) = VersionSection::new(&sh, &mut reader) {
            println!("{}", version_info);
        } else {
            println!("No version information found in this file\n");
        }
    }

    if display.relocs || display.all {
        println!("{}", RelocationSections::new(&sh, &mut reader));
    }
}
