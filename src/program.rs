use crate::file::ElfFileHeader;
use crate::reader::{LittleEndian, ReadBytesExt, Reader, Seek};
use std::fmt;

#[derive(Debug, PartialEq, Clone)]
pub enum SegmentType {
    // Program header table entry unused
    Null,
    // Loadable program segment
    Load,
    // Dynamic linking information
    Dynamic,
    // Program interpreter
    Interp,
    // Auxiliary information
    Note,
    // Reserved
    ShLib,
    // Entry for header table itself
    ProgramHeader,
    // Thread-local storage segment
    ThreadLocalStorage,
    // GCC .eh_frame_hdr segment
    GnuEhFrame,
    // Indicates stack executability
    GnuStack,
    // Read-only after relocation
    GnuRelRo,
    // Unknown
    Unknown(u32),
}

#[derive(Debug, Clone)]
pub struct ProgramHeader {
    // Segment typub pe
    pub p_type: SegmentType,
    // Segment flags
    pub p_flags: u32,
    // Segment file offset
    pub p_offset: u64,
    // Segment virtual address
    pub p_vaddr: u64,
    // Segment pub physical address
    pub p_paddr: u64,
    // Segment size in file
    pub p_filesz: u64,
    // Segment size in memory
    pub p_memsiz: u64,
    // Segment alignment
    pub p_align: u64,
}

#[derive(Debug)]
pub struct ProgramHeaders {
    pub headers: Vec<ProgramHeader>,
}

impl SegmentType {
    fn new(value: u32) -> SegmentType {
        use SegmentType::*;

        match value {
            0 => Null,
            1 => Load,
            2 => Dynamic,
            3 => Interp,
            4 => Note,
            5 => ShLib,
            6 => ProgramHeader,
            7 => ThreadLocalStorage,
            0x6474e550 => GnuEhFrame,
            0x6474e551 => GnuStack,
            0x6474e552 => GnuRelRo,
            _ => Unknown(value),
        }
    }
}

impl ProgramHeader {
    fn new(reader: &mut Reader) -> ProgramHeader {
        ProgramHeader {
            p_type: SegmentType::new(reader.read_u32::<LittleEndian>().unwrap()),
            p_flags: reader.read_u32::<LittleEndian>().unwrap(),
            p_offset: reader.read_u64::<LittleEndian>().unwrap(),
            p_vaddr: reader.read_u64::<LittleEndian>().unwrap(),
            p_paddr: reader.read_u64::<LittleEndian>().unwrap(),
            p_filesz: reader.read_u64::<LittleEndian>().unwrap(),
            p_memsiz: reader.read_u64::<LittleEndian>().unwrap(),
            p_align: reader.read_u64::<LittleEndian>().unwrap(),
        }
    }
}

impl ProgramHeaders {
    pub fn get_all(&self, kind: SegmentType) -> Vec<ProgramHeader> {
        let mut headers: Vec<ProgramHeader> = vec![];

        for header in &self.headers {
            if header.p_type == kind {
                headers.push(header.clone());
            }
        }

        headers
    }

    pub fn new(header: &ElfFileHeader, mut reader: &mut Reader) -> ProgramHeaders {
        reader
            .seek(std::io::SeekFrom::Start(header.e_phoff))
            .unwrap();

        let mut headers: Vec<ProgramHeader> = vec![];
        let mut section_no: u16 = 0;

        while section_no < header.e_phnum {
            headers.push(ProgramHeader::new(&mut reader));
            section_no += 1;
        }

        ProgramHeaders { headers }
    }
}

impl fmt::Display for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // NOTE: we have to use `format!` because Debug ignores padding
        write!(f, "{:16}", format!("{:?}", self.p_type))?;
        write!(f, "{:#016x} ", self.p_offset)?;
        write!(f, "{:#016x} ", self.p_vaddr)?;
        writeln!(f, "{:#016x} ", self.p_paddr)?;

        write!(f, "{:16}{:#016x} ", "", self.p_filesz)?;
        write!(f, "{:#016x} ", self.p_memsiz)?;

        let mut flags = String::new();

        let mut matchflag = |flag: u32, ch: char| {
            if self.p_flags & flag == flag {
                flags.push(ch);
            } else {
                flags.push(' ');
            }
            flags.push(' ');
        };

        matchflag(1 << 0, 'X');
        matchflag(1 << 1, 'W');
        matchflag(1 << 2, 'R');

        write!(f, "{}  ", flags)?;
        writeln!(f, "{:#08x}", self.p_align)
    }
}

impl fmt::Display for ProgramHeaders {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Program Headers:")?;
        writeln!(
            f,
            "{:16}{:16} {:16} {:16}",
            "Type", "Offset", "VirtAddr", "PhysAddr"
        )?;
        writeln!(
            f,
            "{:16}{:16} {:16} {:8}{:8}",
            "", "FileSiz", "MemSiz", "Flags", "Align"
        )?;

        let mut result: fmt::Result = Ok(());

        for header in &self.headers {
            result = header.fmt(f);
        }

        result
    }
}
