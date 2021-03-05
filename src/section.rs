use crate::file::ElfFileHeader;
use crate::reader::{LittleEndian, ReadBytesExt, Reader, Seek, SeekFrom};
use crate::symbols::StringTable;
use std::fmt;

// XXX: use something like bitset
fn sh_flags(value: u64) -> String {
    let mut flags = String::from("");

    let mut matchflag = |flag: u64, ch: char| {
        if value & flag == flag {
            flags.push(ch);
        }
    };

    // Writable
    matchflag(1 << 0, 'W');
    // Occupies memory during execution
    matchflag(1 << 1, 'A');
    // Executable
    matchflag(1 << 2, 'E');
    // Might be merged
    matchflag(1 << 4, 'M');
    // Strings
    matchflag(1 << 5, 'S');
    // `sh_info' contains SHT index
    matchflag(1 << 6, 'I');
    // Preserve order after combining
    matchflag(1 << 7, 'L');
    // Non-standard OS specific handling
    matchflag(1 << 8, 'O');
    // Section is member of group
    matchflag(1 << 9, 'G');
    // Section hold thread-local data
    matchflag(1 << 10, 'T');
    // Section with compressed data
    matchflag(1 << 11, 'C');

    flags
}

#[derive(Debug, Clone)]
pub struct SectionHeader {
    // Section name (string tbl index)
    pub sh_name: u32,
    // Section type
    pub sh_type: SectionHeaderType,
    // Section flags
    pub sh_flags: u64,
    // Section virtual address at execution
    pub sh_addr: u64,
    // Section file offset
    pub sh_offset: u64,
    // Section size in bytes
    pub sh_size: u64,
    // Link to another section
    pub sh_link: u32,
    // Additional section information
    pub sh_info: u32,
    // Section Alignment
    pub sh_addralign: u64,
    // Entry size if section holds the table
    pub sh_entsize: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SectionHeaderType {
    // Section header table entry unused
    Null,
    // Program data
    Data,
    // Symbol table
    Symtab,
    // String table
    Strtab,
    // Relocation entries with addends
    Rela,
    // Symbol hash table
    Hash,
    // Dynamic linking information
    Dynamic,
    // Notes
    Note,
    // Program space with no data (bss)
    Bss,
    // Relocation entries, no adends
    Rel,
    // Dynamic linker symbol table
    DynSym,
    // Array of constructors
    InitArray,
    // Array of destructors
    FiniArray,
    // Array of pre-constructors
    PreInitArray,
    // Section group
    Group,
    // Extended section indeces
    SymtabShndx,
    // Object attributes
    GnuAttributes,
    // Gnu-style hash table
    GnuHash,
    // Prelink library list
    GnuLibList,
    // Checksum for DSO content
    Checksum,
    // Version definition section
    GnuVerDef,
    // Version needs section
    GnuVerNeed,
    // Version symbol table
    GnuVerSym,
    Unknown(u32),
}

#[derive(Debug)]
pub struct SectionHeaders {
    pub headers: Vec<SectionHeader>,
    pub strtab: StringTable,
}

impl SectionHeader {
    fn new(reader: &mut Reader) -> SectionHeader {
        SectionHeader {
            sh_name: reader.read_u32::<LittleEndian>().unwrap(),
            sh_type: SectionHeaderType::new(reader.read_u32::<LittleEndian>().unwrap()),
            sh_flags: reader.read_u64::<LittleEndian>().unwrap(),
            sh_addr: reader.read_u64::<LittleEndian>().unwrap(),
            sh_offset: reader.read_u64::<LittleEndian>().unwrap(),
            sh_size: reader.read_u64::<LittleEndian>().unwrap(),
            sh_link: reader.read_u32::<LittleEndian>().unwrap(),
            sh_info: reader.read_u32::<LittleEndian>().unwrap(),
            sh_addralign: reader.read_u64::<LittleEndian>().unwrap(),
            sh_entsize: reader.read_u64::<LittleEndian>().unwrap(),
        }
    }
}

impl SectionHeaderType {
    fn new(value: u32) -> SectionHeaderType {
        use SectionHeaderType::*;

        match value {
            0 => Null,
            1 => Data,
            2 => Symtab,
            3 => Strtab,
            4 => Rela,
            5 => Hash,
            6 => Dynamic,
            7 => Note,
            8 => Bss,
            9 => Rel,
            11 => DynSym,
            14 => InitArray,
            15 => FiniArray,
            16 => PreInitArray,
            17 => Group,
            18 => SymtabShndx,
            0x6ffffff5 => GnuAttributes,
            0x6ffffff6 => GnuHash,
            0x6ffffff7 => GnuLibList,
            0x6ffffff8 => Checksum,
            0x6ffffffd => GnuVerDef,
            0x6ffffffe => GnuVerNeed,
            0x6fffffff => GnuVerSym,
            _ => Unknown(value),
        }
    }
}

impl SectionHeaders {
    pub fn new(header: &ElfFileHeader, mut reader: &mut Reader) -> SectionHeaders {
        reader.seek(SeekFrom::Start(header.e_shoff)).unwrap();

        let mut headers: Vec<SectionHeader> = vec![];
        let mut section_no: u16 = 0;

        while section_no < header.e_shnum {
            headers.push(SectionHeader::new(&mut reader));
            section_no += 1;
        }

        let strtab: StringTable;

        if header.e_shnum > 0 {
            strtab = StringTable::new(&headers[header.e_shstrndx as usize], &mut reader);
        } else {
            strtab = StringTable::empty();
        }

        SectionHeaders { headers, strtab }
    }

    pub fn get_all(&self, header_type: SectionHeaderType) -> Vec<SectionHeader> {
        let mut result: Vec<SectionHeader> = Vec::new();

        for header in &self.headers {
            if header.sh_type == header_type {
                result.push(header.clone());
            }
        }

        result
    }

    pub fn get(&self, header_type: SectionHeaderType) -> Option<SectionHeader> {
        self.get_all(header_type).pop()
    }

    pub fn get_by_index(&self, index: usize) -> SectionHeader {
        self.headers[index].clone()
    }

    pub fn dynstr(&self, reader: &mut Reader) -> Option<StringTable> {
        for header in &self.headers {
            if header.sh_type != SectionHeaderType::Strtab {
                continue;
            }

            let name = self.strtab.get(header.sh_name as u64);

            if name != String::from(".dynstr") {
                continue;
            }

            return Some(StringTable::new(header, reader));
        }

        None
    }
}

impl fmt::Display for SectionHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Section headers:")?;
        writeln!(
            f,
            "[No] {:<16} {:<16} {:<16} {:<8}",
            "Name", "Type", "Address", "Offset"
        )?;
        writeln!(
            f,
            "     {:<16} {:<16} {:<5} {} {}  {:<8}",
            "Size", "EntSize", "Flags", "Link", "Info", "Align"
        )?;

        for (i, header) in self.headers.iter().enumerate() {
            let name = self.strtab.get(header.sh_name as u64);

            writeln!(
                f,
                "[{:02}] {:16} {:<16} {:#016x} {:#08x}",
                i,
                name,
                format!("{:?}", header.sh_type),
                header.sh_addr,
                header.sh_offset
            )?;
            writeln!(
                f,
                "     {:#016x} {:#016x} {:6} {:<3} {:<4}  {:<6}",
                header.sh_size,
                header.sh_entsize,
                sh_flags(header.sh_flags),
                header.sh_link,
                header.sh_info,
                header.sh_addralign
            )?;
        }

        return Ok(());
    }
}
