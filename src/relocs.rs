use crate::reader::{LittleEndian, ReadBytesExt, Reader, Seek, SeekFrom};
use crate::section::{SectionHeader, SectionHeaderType, SectionHeaders};
use crate::symbols::SymbolTable;
use std::fmt;

fn amd64_relocs(value: u32) -> &'static str {
    match value {
        /* No reloc */
        0 => "R_X86_64_NONE",
        /* Direct 64 bit */
        1 => "R_X86_64_64",
        /* PC relative 32 bit signed */
        2 => "R_X86_64_PC32",
        /* 32 bit GOT entry */
        3 => "R_X86_64_GOT32",
        /* 32 bit PLT address */
        4 => "R_X86_64_PLT32",
        /* Copy symbol at runtime */
        5 => "R_X86_64_COPY",
        /* Create GOT entry */
        6 => "R_X86_64_GLOB_DAT",
        /* Create PLT entry */
        7 => "R_X86_64_JUMP_SLOT",
        /* Adjust by program base */
        8 => "R_X86_64_RELATIVE",
        /* 32 bit signed PC relative offset to GOT */
        9 => "R_X86_64_GOTPCREL",
        /* Direct 32 bit zero extended */
        10 => "R_X86_64_32",
        /* Direct 32 bit sign extended */
        11 => "R_X86_64_32S",
        /* Direct 16 bit zero extended */
        12 => "R_X86_64_16",
        /* 16 bit sign extended pc relative */
        13 => "R_X86_64_PC16",
        /* Direct 8 bit sign extended */
        14 => "R_X86_64_8",
        /* 8 bit sign extended pc relative */
        15 => "R_X86_64_PC8",
        /* ID of module containing symbol */
        16 => "R_X86_64_DTPMOD64",
        /* Offset in module's TLS block */
        17 => "R_X86_64_DTPOFF64",
        /* Offset in initial TLS block */
        18 => "R_X86_64_TPOFF64",
        /* 32 bit signed PC relative offset to two GOT entries for GD symbol */
        19 => "R_X86_64_TLSGD",
        /* 32 bit signed PC relative offset to two GOT entries for LD symbol */
        20 => "R_X86_64_TLSLD",
        /* Offset in TLS block */
        21 => "R_X86_64_DTPOFF32",
        /* 32 bit signed PC relative offset to GOT entry for IE symbol */
        22 => "R_X86_64_GOTTPOFF",
        /* Offset in initial TLS block */
        23 => "R_X86_64_TPOFF32",
        /* PC relative 64 bit */
        24 => "R_X86_64_PC64",
        /* 64 bit offset to GOT */
        25 => "R_X86_64_GOTOFF64",
        /* 32 bit signed pc relative offset to GOT */
        26 => "R_X86_64_GOTPC32",
        /* 64-bit GOT entry offset */
        27 => "R_X86_64_GOT64",
        /* 64-bit PC relative offset to GOT entry */
        28 => "R_X86_64_GOTPCREL64",
        /* 64-bit PC relative offset to GOT */
        29 => "R_X86_64_GOTPC64",
        /* like GOT64, says PLT entry needed */
        30 => "R_X86_64_GOTPLT64",
        /* 64-bit GOT relative offset to PLT entry */
        31 => "R_X86_64_PLTOFF64",
        /* Size of symbol plus 32-bit addend */
        32 => "R_X86_64_SIZE32",
        /* Size of symbol plus 64-bit addend */
        33 => "R_X86_64_SIZE64",
        /* GOT offset for TLS descriptor. */
        34 => "R_X86_64_GOTPC32_TLSDESC",
        /* Marker for call through TLS descriptor. */
        35 => "R_X86_64_TLSDESC_CALL",
        /* TLS descriptor. */
        36 => "R_X86_64_TLSDESC",
        /* Adjust indirectly by program base */
        37 => "R_X86_64_IRELATIVE",
        /* 64-bit adjust by program base */
        38 => "R_X86_64_RELATIVE64",
        /* Load from 32 bit signed pc relative offset to GOT entry without REX prefix, relaxable. */
        41 => "R_X86_64_GOTPCRELX",
        /* Load from 32 bit signed pc relative offset to GOT entry with REX prefix, relaxable. */
        42 => "R_X86_64_REX_GOTPCRELX",
        _ => "Unknown",
    }
}

#[derive(Debug)]
pub struct RelocationEntry {
    // Address
    offset: u64,
    // Relocation type
    reltype: u32,
    // Symbol index
    symidx: u32,
    // Addend (present only for Rela section)
    addend: Option<i64>,
}

#[derive(Debug)]
pub struct RelocationSection {
    pub entries: Vec<RelocationEntry>,
    pub symtab: SymbolTable,
    pub name: String,
    pub kind: SectionHeaderType,
}

#[derive(Debug)]
pub struct RelocationSections {
    pub sections: Vec<RelocationSection>,
}

impl RelocationEntry {
    fn new(reader: &mut Reader, has_addend: bool) -> RelocationEntry {
        let offset = reader.read_u64::<LittleEndian>().unwrap();
        let reltype = reader.read_u32::<LittleEndian>().unwrap();
        let symidx = reader.read_u32::<LittleEndian>().unwrap();
        let addend = if has_addend {
            Some(reader.read_i64::<LittleEndian>().unwrap())
        } else {
            None
        };

        RelocationEntry {
            offset,
            reltype,
            symidx,
            addend,
        }
    }
}

impl RelocationSection {
    pub fn new(
        header: &SectionHeader,
        name: String,
        symtab: SymbolTable,
        reader: &mut Reader,
    ) -> RelocationSection {
        let mut entries = vec![];
        let mut offset = 0;

        while offset < header.sh_size {
            reader
                .seek(SeekFrom::Start(header.sh_offset + offset))
                .unwrap();

            let has_addend = header.sh_type == SectionHeaderType::Rela;

            entries.push(RelocationEntry::new(reader, has_addend));
            offset += header.sh_entsize;
        }

        RelocationSection {
            symtab: symtab,
            name: name,
            entries: entries,
            kind: header.sh_type.clone(),
        }
    }
}

impl RelocationSections {
    pub fn new(headers: &SectionHeaders, mut reader: &mut Reader) -> RelocationSections {
        let mut sections: Vec<RelocationSection> = vec![];

        let mut rel_headers = headers.get_all(SectionHeaderType::Rel);
        rel_headers.extend(headers.get_all(SectionHeaderType::Rela));

        for header in &rel_headers {
            let symtab_header = headers.get_by_index(header.sh_link as usize);

            let name = headers.strtab.get(header.sh_name as u64);
            let symtab = SymbolTable::new(&headers, &symtab_header, &mut reader);

            sections.push(RelocationSection::new(&header, name, symtab, reader));
        }

        RelocationSections { sections }
    }
}

impl fmt::Display for RelocationSections {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = Ok(());

        for section in &self.sections {
            result = section.fmt(f);
            writeln!(f, "")?;
        }
        result
    }
}

impl fmt::Display for RelocationSection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "Relocation section `{}' contains {} entries:",
            self.name,
            self.entries.len()
        )?;

        writeln!(
            f,
            "{:<6} {:<12} {:<20} {:<12} {:<16}",
            "Num", "Sym. Size", "Sym. Type", "Sym. Bind", "Sym. Vis",
        )?;
        writeln!(
            f,
            "       {:<12} {:<20} {:<12} {:<16} {:<16}",
            "Offset", "Type", "Sym. Value", "Addend", "Sym. Name"
        )?;

        for (n, entry) in self.entries.iter().enumerate() {
            let (name, symbol) = self.symtab.get_by_index(entry.symidx as usize);

            let typ = format!("{:?}", symbol.st_type);
            let bin = format!("{:?}", symbol.st_bind);
            let vis = format!("{:?}", symbol.st_vis);

            writeln!(
                f,
                "{:<06} {:#012x} {:<20} {:<12} {:16}",
                n, symbol.st_size, typ, bin, vis
            )?;

            let addend = if entry.addend.is_some() {
                entry.addend.unwrap()
            } else {
                0
            };

            writeln!(
                f,
                "       {:#012x} {:<20} {:#012x} {:#016x} {} ",
                entry.offset,
                amd64_relocs(entry.reltype),
                symbol.st_value,
                addend,
                name
            )?;
        }
        Ok(())
    }
}
