use crate::reader::{LittleEndian, ReadBytesExt, Reader, Seek, SeekFrom};
use crate::section::{SectionHeader, SectionHeaderType, SectionHeaders};
use std::fmt;
use std::io::Read;

#[derive(Debug)]
pub struct StringTable {
    // XXX: we cannot use map with offsets, because some sections
    //      point to the middle of another string
    buffer: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Symbol {
    // Symbol name (pub string tbl index)
    pub st_name: u32,
    // Symbol type
    pub st_type: SymbolType,
    // Symbol binding
    pub st_bind: SymbolBinding,
    // Symbol visibility
    pub st_vis: SymbolVisibility,
    // Section index
    pub st_shndx: u16,
    // Symbol value
    pub st_value: u64,
    // Symbol size
    pub st_size: u64,
}

#[derive(Debug, Clone)]
pub enum SymbolType {
    // SymboType is unspecified
    NoType,
    // Symbol is a data object
    Object,
    // Symbol is a code object
    Func,
    // Symbol associated with a section
    Section,
    // Symbol's name is file name
    File,
    // Symbol is a common data object
    Common,
    // Symbol is thread-local data object
    Tls,
    // Symbol is indirect code object
    GnuIndFun,
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub enum SymbolBinding {
    // Local symbol
    Local,
    // Global symbol
    Global,
    // Weak symbol
    Weak,
    // Unique Symbol
    GnuUnique,
    // Unknown
    Unknown(u8),
}

#[derive(Debug, Clone)]
pub enum SymbolVisibility {
    // Default symbol visibility rules
    Default,
    // Processor specific hidden class
    Internal,
    // Sym unavailable in other modules
    Hidden,
    // Not preemptible, not exported
    Protected,
}

#[derive(Debug)]
pub struct SymbolTable {
    data: Vec<Symbol>,
    strtab: StringTable,
    name: String,
    symsize: usize,
}

#[derive(Debug)]
pub struct SymbolTables {
    data: Vec<SymbolTable>,
}

impl StringTable {
    // XXX: use some kind of buffer for this
    pub fn get(&self, offset: u64) -> String {
        let sub = &self.buffer[offset as usize..];
        let mut result = String::new();

        for ch in sub.iter() {
            if *ch != 0 {
                result.push(*ch as char);
            } else {
                break;
            }
        }

        result
    }

    pub fn empty() -> StringTable {
        StringTable { buffer: vec![] }
    }

    pub fn new(hdr: &SectionHeader, reader: &mut Reader) -> StringTable {
        reader.seek(SeekFrom::Start(hdr.sh_offset)).unwrap();

        let mut handle = reader.take(hdr.sh_size);
        let mut buffer: Vec<u8> = Vec::new();

        handle.read_to_end(&mut buffer).unwrap();

        StringTable { buffer }
    }
}

impl Symbol {
    pub fn new(reader: &mut Reader) -> Symbol {
        let st_name = reader.read_u32::<LittleEndian>().unwrap();

        let st_info = reader.read_u8().unwrap();
        let st_type = SymbolType::new(st_info);
        let st_bind = SymbolBinding::new(st_info);

        let st_other = reader.read_u8().unwrap();
        let st_vis = SymbolVisibility::new(st_other);

        let st_shndx = reader.read_u16::<LittleEndian>().unwrap();
        let st_value = reader.read_u64::<LittleEndian>().unwrap();
        let st_size = reader.read_u64::<LittleEndian>().unwrap();

        Symbol {
            st_name,
            st_type,
            st_bind,
            st_vis,
            st_shndx,
            st_value,
            st_size,
        }
    }
}

impl SymbolType {
    fn new(info: u8) -> SymbolType {
        use SymbolType::*;

        match info & 0xf {
            0 => NoType,
            1 => Object,
            2 => Func,
            3 => Section,
            4 => File,
            5 => Common,
            6 => Tls,
            10 => GnuIndFun,
            _ => Unknown(info & 0xf),
        }
    }
}

impl SymbolBinding {
    fn new(info: u8) -> SymbolBinding {
        use SymbolBinding::*;

        match info >> 4 {
            0 => Local,
            1 => Global,
            2 => Weak,
            10 => GnuUnique,
            _ => Unknown(info >> 4),
        }
    }
}

impl SymbolVisibility {
    fn new(other: u8) -> SymbolVisibility {
        use SymbolVisibility::*;

        match other & 0x3 {
            0 => Default,
            1 => Internal,
            2 => Hidden,
            3 => Protected,
            // NOTE: this is just because compiler complained
            _ => Default,
        }
    }
}

impl SymbolTable {
    pub fn new(
        headers: &SectionHeaders,
        header: &SectionHeader,
        mut reader: &mut Reader,
    ) -> SymbolTable {
        // XXX: check that header.sh_type is SHT_SYMTAB or SHT_DYNSYM
        reader.seek(SeekFrom::Start(header.sh_offset)).unwrap();

        let mut data = vec![];
        let mut i = 0;

        // XXX: use some better method for checking the end
        while i < header.sh_size {
            i += header.sh_entsize;
            data.push(Symbol::new(&mut reader));
        }

        let strtab = &headers.headers[header.sh_link as usize];
        let name = headers.strtab.get(header.sh_name as u64);

        SymbolTable {
            data,
            name,
            strtab: StringTable::new(&strtab, reader),
            symsize: header.sh_entsize as usize,
        }
    }

    pub fn get_by_index(&self, index: usize) -> (String, Symbol) {
        let sym = self.data.get(index).unwrap();
        let name = self.strtab.get(sym.st_name as u64);

        (name, sym.clone())
    }
}

impl SymbolTables {
    pub fn new(headers: &SectionHeaders, reader: &mut Reader) -> SymbolTables {
        let mut data: Vec<SymbolTable> = vec![];

        for header in &headers.headers {
            if header.sh_type == SectionHeaderType::DynSym
                || header.sh_type == SectionHeaderType::Symtab
            {
                data.push(SymbolTable::new(headers, &header, reader));
            }
        }

        SymbolTables { data }
    }
}

impl fmt::Display for SymbolTables {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = Ok(());

        for symtab in &self.data {
            result = symtab.fmt(f);
            writeln!(f)?;
        }
        result
    }
}

impl fmt::Display for SymbolTable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "Symbol table `{}` contains {} entries:",
            self.name,
            self.data.len()
        )?;
        writeln!(
            f,
            "{:<6} {:<16} {:<8} {:<8} {:<6} {:<9} {:<3} Name",
            "Num", "Value", "Size", "Type", "Bind", "Vis", "Ndx"
        )?;

        for (i, sym) in self.data.iter().enumerate() {
            let name = self.strtab.get(sym.st_name as u64);
            let typ = format!("{:?}", sym.st_type);
            let bin = format!("{:?}", sym.st_bind);
            let vis = format!("{:?}", sym.st_vis);

            let ndx = if sym.st_shndx == 65521 {
                String::from("Und")
            } else {
                format!("{:03}", sym.st_shndx)
            };

            writeln!(
                f,
                "{:<06} {:#016x} {:#08x} {:<8} {:<6} {:9} {:3} {}",
                i, sym.st_value, sym.st_size, typ, bin, vis, ndx, name
            )?;
        }
        Ok(())
    }
}
