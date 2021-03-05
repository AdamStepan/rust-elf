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

struct DisplayOptions {
    file_header: bool,
    program_headers: bool,
    section_headers: bool,
    symbols: bool,
    notes: bool,
    dynamic: bool,
    version_info: bool,
    interpret: bool,
    relocs: bool,
}

fn main() {
    use clap::clap_app;
    use std::fs::File;

    let matches = clap_app!(readelf =>
        (version: "0.8")
        (author: "Adam S. <adam.stepan@firma.seznam.cz>")
        (about: "Display information about ELF files")
        (@arg all: -a --all "Equivalent to: -h -l -S -s -d -V -i")
        (@arg ("file-header"): -h --("file-header") "Display the ELF file header")
        (@arg interpret: -i --interpret "Display data of .interp section")
        (@arg ("program-headers"): -l --("program-headers") "Display the program headers")
        (@arg ("section-headers"): -S --("section-headers") "Display the sections' header")
        (@arg symbols: -s --("symbols") "Display the symbol table")
        (@arg notes: --notes "Display notes")
        (@arg dynamic: -d --dynamic "Display the dynamic section")
        (@arg ("version-info"): -V --("version-info") "Display the version sections")
        (@arg relocs: -r --relocs "Display the relocations")
        (@arg file: +required "elf-file")
    )
    .get_matches();

    let filename = matches.value_of("file").unwrap();

    let mut file = File::open(filename).unwrap();
    let mut buffer = Vec::new();

    let all = matches.is_present("all");

    let display = DisplayOptions {
        file_header: matches.is_present("file-header") || all,
        interpret: matches.is_present("interpret") || all,
        program_headers: matches.is_present("program-headers") || all,
        section_headers: matches.is_present("section-headers") || all,
        symbols: matches.is_present("symbols") || all,
        notes: matches.is_present("notes") || all,
        dynamic: matches.is_present("dynamic") || all,
        version_info: matches.is_present("version-info") || all,
        relocs: matches.is_present("relocs"), // ignore all for now
    };

    file.read_to_end(&mut buffer).unwrap();

    let mut reader = Cursor::new(buffer);

    let fh = ElfFileHeader::new(&mut reader);
    let ph = ProgramHeaders::new(&fh, &mut reader);
    let sh = SectionHeaders::new(&fh, &mut reader);

    if display.file_header {
        println!("{}", fh);
    }

    if display.program_headers {
        println!("{}", ph);
    }

    if display.section_headers {
        println!("{}", sh);
    }

    if display.interpret {
        println!("{}", Interpret::new(&ph, &mut reader));
    }

    if display.symbols {
        println!("{}", SymbolTables::new(&sh, &mut reader));
    }

    if display.notes {
        let addrsize = match fh.e_class {
            FileClass::ElfClass64 => 8,
            FileClass::ElfClass32 => 4,
            _ => panic!("Unable to determine elf file class"),
        };
        println!("{}", NoteSections::new(addrsize, &sh, &ph, &mut reader));
    }

    if display.dynamic {
        if let Some(dynamic) = DynamicSection::new(&sh, &mut reader) {
            println!("{}", dynamic);
        } else {
            println!("There is no dynamic section in this file\n");
        }
    }

    if display.version_info {
        if let Some(version_info) = VersionSection::new(&sh, &mut reader) {
            println!("{}", version_info);
        } else {
            println!("No version information found in this file\n");
        }
    }

    if display.relocs {
        println!("{}", RelocationSections::new(&sh, &mut reader));
    }
}
