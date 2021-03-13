use crate::program::{ProgramHeader, ProgramHeaders, SegmentType};
use crate::reader::{Cursor, LittleEndian, ReadBytesExt, Reader, Seek, SeekFrom};
use crate::section::{SectionHeader, SectionHeaderType, SectionHeaders};
use std::io::Read;
use anyhow::{Result, Context, bail};
use std::fmt;

fn align_up(size: u64, align: u64) -> u64 {
    /* Some PT_NOTE segment may have alignment value of 0
     * or 1. ABI specifies that PT_NOTE segments should be
     * aligned to 4 bytes in 32-bit objects and to 8 bytes in
     * 64-bit objects.
     */
    let align = if align <= 4 { 4 } else { align };

    (size + align - 1) & !(align - 1)
}

/* sizeof(Elf64_Nhdr)
 * typedef struct {
 *    Elf64_Word n_namesz;
 *    Elf64_Word n_descsz;
 *    Elf64_Word n_type;
 * } Elf64_Nhdr;
 */
const ELF_NOTE_SIZE: u64 = 3 * 4;

fn note_desc_offset(namesz: u64, align: u64) -> u64 {
    align_up(ELF_NOTE_SIZE + namesz, align)
}

fn note_next_offset(namesz: u64, descsz: u64, align: u64) -> u64 {
    align_up(note_desc_offset(namesz, align) + descsz, align)
}

fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join(" ")
}

#[derive(Debug)]
struct Note {
    // Length of the note's name
    name_size: u32,
    // Lenght of the note's descriptor
    desc_size: u32,
    // Type of the note
    note_type: NoteType,
    // Name of the note
    name: String,
    // Descriptor data
    desc: NoteDesc,
}

// There is multiple note types: core, gnu, linux, other
#[derive(Debug)]
enum NoteType {
    // Note Types for GNU systems

    // ABI information
    ElfNoteAbi,
    // Synthetic hwcap information
    GnuHwCap,
    // Build ID bits as generated by ld --build-id
    GnuBuildID,
    // Version note generated by GNU gold containing a version
    // string
    GnuGoldVersion,
    // Program property
    GnuProperty,

    // Descriptor types for core files

    // Contains copy of prstatus struct
    PrStatus,
    // Contains copy of fpregset struct
    PrFpReg,
    // Contains copy of prpsinfo struct
    PrPsInfo,
    // Contains copy of task structure
    TaskStruct,
    // String from sysinfo(SI_PLATFORM)
    Platform,
    // Contains copy of auxv array
    Auxw,
    // Contains copy of gwindows struct
    GWindows,
    // Contains copy of asrset struct
    AsRet,
    // Contains copy of pstatus struct
    PsStatus,
    // Contains copy of psinfo struct
    PsInfo,
    // Contains copy of prcred struct
    PrcRed,
    // Contains copy of utsname struct
    UtsName,
    // Contains copy of lwpstatus struct
    LwpStatus,
    // Contains copy of lwpinfo struct
    LwpInfo,
    // Contains copy of fprxregset struct
    FprxRegSet,
    // Contains copy of siginfo_t, size might increase
    SigInfo,
    // Contains information about mapped files
    MappedFiles,
    // x86 extended state using xsave
    X86ExtendedState,

    // Note types for object files
    Version,

    // Unknown
    Unknown(u32),
}

#[derive(Debug)]
struct MappedFile {
    start: u64,
    end: u64,
    page_offset: u64,
    filename: String,
}

#[derive(Debug)]
struct MappedFiles {
    count: u64,
    pagesize: u64,
    files: Vec<MappedFile>,
}

#[derive(Debug)]
enum NoteDesc {
    // ABI information
    ElfNoteAbi {
        // Os descriptor
        os: NoteOs,
        // Major version of the ABI
        major: u32,
        // Minor version of the ABI
        minor: u32,
        // Patch version of the ABI
        patch: u32,
    },
    // Synthetic hwcap information
    // The descriptor begins with two words:
    // word 0: number of entries
    // word 1: bitmask of enable entries
    //
    // Then follow variable-length entries, one byte followed by
    // '\0'-terminated hwcap name string.
    //
    // The bytes gives the bit number to test if enabled
    GnuHwCap(Vec<u8>),
    // Build ID bits as generated by ld --build-id
    // The descriptor conists of any nonzero number of bytes
    GnuBuildID(String),
    // Version note generated by GNU gold containing a version
    // string
    GnuGoldVersion(String),
    // Program property
    GnuProperty(Vec<u8>),
    MappedFiles(MappedFiles),
    Unknown(Vec<u8>),
}

// Note section contents.
// Each entry in the note sections begins with a header of fixed form.
#[derive(Debug)]
struct NoteSection {
    data: Vec<Note>,
    name: String,
}

#[derive(Debug)]
pub struct NoteSections {
    data: Vec<NoteSection>,
}

#[derive(Debug)]
enum NoteOs {
    Linux,
    Gnu,
    Solaris2,
    FreeBsd,
    Unknown(u32),
}

#[derive(Debug)]
enum NoteOwner {
    Gnu,
    Core,
    // FreeBSD, NetBSD, ...
    Unknown,
}

impl NoteOwner {
    fn new(name: &str) -> NoteOwner {
        use NoteOwner::*;
        match name {
            "GNU\0" => Gnu,
            "LINUX\0" | "CORE\0" => Core,
            _ => Unknown,
        }
    }
}

impl Note {
    pub fn new(addrsize: u8, align: u64, reader: &mut Reader) -> Result<Note> {
        let name_size = reader.read_u32::<LittleEndian>()?;
        let desc_size = reader.read_u32::<LittleEndian>()?;

        let type_ = reader.read_u32::<LittleEndian>()?;

        let mut name_ = vec![0; name_size as usize];
        reader.read_exact(&mut name_)?;

        let cur = name_size + ELF_NOTE_SIZE as u32;
        let off = note_desc_offset(name_size.into(), align) - cur as u64;

        reader.seek(SeekFrom::Current(off as i64))?;

        let mut desc_ = vec![0; desc_size as usize];
        reader.read_exact(&mut desc_)?;

        let name = String::from_utf8(name_)?;
        let owner = NoteOwner::new(&name);

        let note_type = match owner {
            NoteOwner::Gnu => NoteType::gnu(type_),
            NoteOwner::Core => NoteType::core(type_),
            NoteOwner::Unknown => NoteType::default(type_),
        };

        let desc = match owner {
            NoteOwner::Gnu => NoteDesc::gnu(&note_type, desc_),
            NoteOwner::Core => NoteDesc::core(&note_type, desc_, addrsize)?,
            NoteOwner::Unknown => NoteDesc::default(desc_),
        };

        Ok(Note {
            name_size,
            desc_size,
            note_type,
            name,
            desc,
        })
    }
}

impl NoteType {
    fn gnu(value: u32) -> NoteType {
        use NoteType::*;

        match value {
            1 => ElfNoteAbi,
            2 => GnuHwCap,
            3 => GnuBuildID,
            4 => GnuGoldVersion,
            5 => GnuProperty,
            _ => Unknown(value),
        }
    }

    fn core(value: u32) -> NoteType {
        use NoteType::*;

        match value {
            1 => PrStatus,
            2 => PrFpReg,
            3 => PrPsInfo,
            4 => TaskStruct,
            5 => Platform,
            6 => Auxw,
            7 => GWindows,
            8 => AsRet,
            10 => PsStatus,
            13 => PsInfo,
            14 => PrcRed,
            15 => UtsName,
            16 => LwpStatus,
            17 => LwpInfo,
            20 => FprxRegSet,
            0x53494749 => SigInfo,
            0x46494c45 => MappedFiles,
            0x202 => X86ExtendedState,
            _ => Unknown(value),
        }
    }

    fn default(value: u32) -> NoteType {
        use NoteType::*;

        match value {
            1 => Version,
            _ => NoteType::Unknown(value),
        }
    }
}

fn read_filenames(reader: &mut Reader, count: u64, addrsize: u64) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut buffer = [0; 1];
    let mut current = String::new();

    let start = (2 * addrsize) + // count + pagesize items
                (count * 3 * addrsize); // start, end, offset for each mapped file

    reader.seek(SeekFrom::Start(start))?;
    for _ in 0..count {
        // read name until we read null byte
        loop {
            reader.read_exact(&mut buffer)?;

            if buffer[0] == 0 {
                break;
            }

            current.push(buffer[0] as char);
        }

        result.push(current.clone());
        current.clear();
    }
    Ok(result)
}

impl MappedFiles {

    fn new(data: Vec<u8>, addrsize: u8) -> Result<MappedFiles> {
        let readaddr = |reader: &mut Reader| -> Result<u64> {
            match addrsize {
                4 => Ok(reader.read_u32::<LittleEndian>()? as u64),
                8 => Ok(reader.read_u64::<LittleEndian>()?),
                _ => bail!("invalid addrsize: {}", addrsize),
            }
        };

        let mut reader = Cursor::new(data);

        let count = readaddr(&mut reader)?;
        let pagesize = readaddr(&mut reader)?;

        let start = reader.position();
        let filenames = read_filenames(&mut reader, count, addrsize as u64)?;

        reader.seek(SeekFrom::Start(start))?;

        let mut files = Vec::new();
        for idx in 0..count {
            files.push(MappedFile {
                start: readaddr(&mut reader)?,
                end: readaddr(&mut reader)?,
                page_offset: readaddr(&mut reader)?,
                filename: filenames.get(idx as usize)
                                   .context("Unable to find filename")?.clone(),
            });
        }

        Ok(MappedFiles {
            count,
            pagesize,
            files,
        })
    }
}

impl NoteDesc {
    fn gnu(value: &NoteType, data: Vec<u8>) -> NoteDesc {
        use NoteDesc::*;

        let asu32 = |index: usize| {
            (data[index] as u32)
                | ((data[index + 1] as u32) << 8)
                | ((data[index + 2] as u32) << 16)
                | ((data[index + 3] as u32) << 24)
        };

        match value {
            NoteType::ElfNoteAbi => ElfNoteAbi {
                os: NoteOs::new(asu32(0)),
                major: asu32(4),
                minor: asu32(8),
                patch: asu32(12),
            },
            NoteType::GnuHwCap => GnuHwCap(data),
            NoteType::GnuBuildID => GnuBuildID(to_hex_string(data)),
            NoteType::GnuGoldVersion => GnuGoldVersion(to_hex_string(data)),
            NoteType::GnuProperty => GnuProperty(data),
            _ => Unknown(data),
        }
    }

    fn core(value: &NoteType, data: Vec<u8>, addrsize: u8) -> Result<NoteDesc> {
        match value {
            NoteType::MappedFiles => Ok(NoteDesc::MappedFiles(MappedFiles::new(data, addrsize)?)),
            _ => Ok(NoteDesc::Unknown(data)),
        }
    }

    fn default(data: Vec<u8>) -> NoteDesc {
        NoteDesc::Unknown(data)
    }
}

impl NoteOs {
    fn new(value: u32) -> NoteOs {
        use NoteOs::*;

        match value {
            0 => Linux,
            1 => Gnu,
            2 => Solaris2,
            3 => FreeBsd,
            _ => Unknown(value),
        }
    }
}

impl NoteSection {
    pub fn new_from_file(
        addrsize: u8,
        offset: u64,
        size: u64,
        align: u64,
        name: Option<String>,
        mut reader: &mut Reader,
    ) -> Result<NoteSection> {
        reader.seek(SeekFrom::Start(offset))?;

        let mut data = vec![];
        let mut pos: u64 = 0;

        while pos < size {
            reader.seek(SeekFrom::Start(offset + pos))?;

            let note = Note::new(addrsize, align, &mut reader)?;
            pos += note_next_offset(note.name_size.into(), note.desc_size.into(), align);

            // last entry
            if note.name_size == 0 {
                break;
            }

            data.push(note);
        }

        Ok(NoteSection {
            data,
            name: name.unwrap_or_else(|| "".to_string()),
        })
    }

    pub fn new_from_core(addrsize: u8, header: &ProgramHeader, reader: &mut Reader) -> Result<NoteSection> {
        Ok(NoteSection::new_from_file(
            addrsize,
            header.p_offset,
            header.p_filesz,
            header.p_align,
            Some("Note program header".into()),
            reader,
        )?)
    }

    pub fn new(
        addrsize: u8,
        header: &SectionHeader,
        name: String,
        reader: &mut Reader,
    ) -> Result<NoteSection> {
        Ok(NoteSection::new_from_file(
            addrsize,
            header.sh_offset,
            header.sh_size,
            header.sh_addralign,
            Some(name),
            reader,
        )?)
    }
}

impl NoteSections {
    pub fn new(
        addrsize: u8,
        headers: &SectionHeaders,
        prheaders: &ProgramHeaders,
        reader: &mut Reader,
    ) -> Result<NoteSections> {
        let mut data: Vec<NoteSection> = vec![];

        for header in &headers.get_all(SectionHeaderType::Note) {
            let name = headers.strtab.get(header.sh_name as u64);
            data.push(NoteSection::new(addrsize, &header, name, reader)?);
        }

        // try to parse notes from program headers
        if data.is_empty() {
            for prheader in &prheaders.get_all(SegmentType::Note) {
                data.push(NoteSection::new_from_core(addrsize, &prheader, reader)?);
            }
        }

        Ok(NoteSections { data })
    }
}

impl fmt::Display for NoteSection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Displaying notes found in: {}", self.name)?;
        writeln!(f, "{:<16} {:<16} {:<32}", "Name", "DescSize", "Desc")?;

        for note in &self.data {
            writeln!(
                f,
                "{:<16}  {:#016x} {:<32}",
                note.name,
                note.desc_size,
                format!("{:?}", note.note_type)
            )?;
            write!(f, "{}", note.desc)?;
        }

        Ok(())
    }
}

impl fmt::Display for NoteDesc {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use NoteDesc::*;

        match &self {
            ElfNoteAbi {
                os,
                major,
                minor,
                patch,
            } => {
                writeln!(f, "  OS: {:?} {}.{}.{}", os, major, minor, patch)?;
            }
            GnuBuildID(id) => writeln!(f, "  BuildID: {}", id)?,
            MappedFiles(files) => {
                writeln!(f, "  Page size: {}", files.pagesize)?;
                writeln!(
                    f,
                    "  {:<16} {:<16} {:<16} {:<16}",
                    "Start", "End", "PageOffset", "Path"
                )?;
                for file in &files.files {
                    writeln!(
                        f,
                        "  {:#016x} {:#016x} {:#016x} {}",
                        file.start, file.end, file.page_offset, file.filename
                    )?;
                }
            }
            _ => {}
        }
        Ok(())
    }
}

impl fmt::Display for NoteSections {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for section in &self.data {
            section.fmt(f)?;
        }
        Ok(())
    }
}