#[macro_use]
extern crate clap;

use byteorder::{LittleEndian, ReadBytesExt};
use std::fmt;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom};

#[derive(Debug)]
struct ElfFileHeader {
    // Conglomeration of the identification bytes, must be \177ELF
    e_magic: [u8; 4],
    // File class
    e_class: FileClass,
    // Data encoding
    e_encoding: Encoding,
    // File version, value must be EV_CURRENT
    e_version_: u8,
    // OS ABI identification
    e_os_abi: OsAbi,
    // ABI version
    e_os_abi_version: u8,
    // Padding bytes
    e_padding_: [u8; 7],
    // Object file type
    e_type: ObjectType,
    // Architecture
    e_machine: u16,
    // Object file version
    e_version: Version,
    // Entry point virtual address
    e_entry: u64,
    // Program header table file offset
    e_phoff: u64,
    // Section header table file offset
    e_shoff: u64,
    // Processor-specific flags
    e_flags: u32,
    // ELF header size in bytes
    e_ehsize: u16,
    // Program header table entry size
    e_phentsize: u16,
    // Program header table entry count
    e_phnum: u16,
    // Section header table entry size
    e_shentsize: u16,
    // Section header table entry count
    e_shnum: u16,
    // Section header string table index
    e_shstrndx: u16,
}

#[derive(Debug)]
enum FileClass {
    // Invalid class
    None,
    // 32-bit objects
    ElfClass32,
    // 64 bit objects
    ElfClass64,
    // Unknown class
    Invalid(u8),
}

#[derive(Debug)]
enum Encoding {
    // Invalid data encoding
    None,
    // 2's complement, little endian
    LittleEndian,
    // 2's complement big endian
    BigEndian,
    // Uknown data encoding
    Invalid(u8),
}

#[derive(Debug)]
enum OsAbi {
    // UNIX System V ABI
    UnixVSystem,
    // HP-UX
    HpUx,
    // NetBDS
    NetBsd,
    // Object uses GNU ELF extensions
    GnuElfExtensions,
    // SUN Solaris
    SunSolaris,
    // IBM AIX
    IbmAix,
    // SGI Irix
    SgiIrix,
    // FreeBSD
    FreeBsd,
    // Compaq TRU64 UNIX
    CompaqTru64Unix,
    // Novell Modesto
    NovellModesto,
    // OpenBSD
    OpenBsd,
    // ARM EABI
    ArmEabi,
    // ARM
    Arm,
    // Standalone (embedded) application
    Standalone,
    // Unknown
    Invalid(u8),
}

#[derive(Debug)]
enum ObjectType {
    // No file type
    NoFileType,
    // Reolcatable file
    RelocatableFile,
    // Executable file
    ExecutableFile,
    // Shared object file
    SharedObjectFile,
    // Core file
    CoreFile,
    // Unknown
    Invalid(u16),
}

#[derive(Debug)]
enum Version {
    // Invalid ELF version
    Unspecified,
    // Current version
    Current,
    // Unknown
    Invalid(u32),
}

#[derive(Debug, Clone)]
struct SectionHeader {
    // Section name (string tbl index)
    sh_name: u32,
    // Section type
    sh_type: SectionHeaderType,
    // Section flags
    sh_flags: u64,
    // Section virtual address at execution
    sh_addr: u64,
    // Section file offset
    sh_offset: u64,
    // Section size in bytes
    sh_size: u64,
    // Link to another section
    sh_link: u32,
    // Additional section information
    sh_info: u32,
    // Section Alignment
    sh_addralign: u64,
    // Entry size if section holds the table
    sh_entsize: u64,
}

#[derive(Debug, Clone, PartialEq)]
enum SectionHeaderType {
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
struct SectionHeaders {
    headers: Vec<SectionHeader>,
    strtab: StringTable,
}

#[derive(Debug)]
struct StringTable {
    // XXX: we cannot use map with offsets, because some sections
    //      point to the middle of another string
    buffer: Vec<u8>,
}

#[derive(Debug)]
struct ProgramHeader {
    // Segment type
    p_type: SegmentType,
    // Segment flags
    p_flags: u32,
    // Segment file offset
    p_offset: u64,
    // Segment virtual address
    p_vaddr: u64,
    // Segment physical address
    p_paddr: u64,
    // Segment size in file
    p_filesz: u64,
    // Segment size in memory
    p_memsiz: u64,
    // Segment alignment
    p_align: u64,
}

#[derive(Debug, PartialEq)]
enum SegmentType {
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

#[derive(Debug)]
struct ProgramHeaders {
    headers: Vec<ProgramHeader>,
}

#[derive(Debug)]
struct Symbol {
    // Symbol name (string tbl index)
    st_name: u32,
    // Symbol type
    st_type: SymbolType,
    // Symbol binding
    st_bind: SymbolBinding,
    // Symbol visibility
    st_vis: SymbolVisibility,
    // Section index
    st_shndx: u16,
    // Symbol value
    st_value: u64,
    // Symbol size
    st_size: u64,
}

#[derive(Debug)]
enum SymbolType {
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

#[derive(Debug)]
enum SymbolBinding {
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

#[derive(Debug)]
enum SymbolVisibility {
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
struct SymbolTable {
    data: Vec<Symbol>,
    strtab: StringTable,
    name: String,
}

#[derive(Debug)]
struct SymbolTables {
    data: Vec<SymbolTable>,
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

#[derive(Debug)]
enum NoteType {
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
    // Unknown
    Unknown(u32),
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
    Unknown(Vec<u8>),
}

#[derive(Debug)]
struct NoteSection {
    data: Vec<Note>,
    name: String,
}

#[derive(Debug)]
struct NoteSections {
    data: Vec<NoteSection>,
}

#[derive(Debug)]
enum NoteOs {
    Linux,
    Gnu,
    Solaris2,
    FreeBsd,
    Unknown(u8),
}

#[derive(Debug)]
struct Interpret {
    path: String,
}

#[derive(Debug)]
struct DynamicEntry {
    // For each object with this type, tag controls the interpretation
    // of the value
    tag: DynamicEntryTag,
    value: u64,
}

#[derive(Debug, PartialEq)]
enum DynamicEntryTag {
    // Marks end of dynamic section
    Null,
    // Offset into the string table recorded in Strtab entry
    Needed,
    // Size in bytes of PLT Relocs
    PltRelocsSize,
    // Processor defined value
    PltGot,
    // Address of symbol hash table
    Hash,
    // Address of string table
    Strtab,
    // Address of symbol table
    Symtab,
    // Address of Rela relocs
    Rela,
    // Total size of Rela reloc
    RelaSize,
    // Size of one Rela reloc
    RelaEntSize,
    // Size of string table
    StrtabSize,
    // Size of one symbol table entry
    SymtabEntSize,
    // Address of init functions
    Init,
    // Address of termination function
    Fini,
    // Name of shared object
    SoName,
    // Library search path (deprecated)
    Rpath,
    // Start symbol search here
    Symbolic,
    // Address of Rel relocs
    Rel,
    // Total size of Rel relocs
    RelSize,
    // Size of one Rel reloc
    RelEntSize,
    // Type of reloc in PLT
    PltRel,
    // For debugging; unspecified
    Debug,
    // Reloc might modify .text
    TextRel,
    // Address of PLT relocs
    JmpRel,
    // Process relocations of object
    BindNow,
    // Array with addresses of init fct
    InitArray,
    // Array with addresses of fini fct
    FiniArray,
    // Size in bytes of InitArray
    InitiArraySize,
    // Size in bytes of FiniArray
    FiniArraySize,
    // Library search path
    RunPath,
    // Flags for object being loaded
    Flags,
    // Start of encoded page
    Encoding,
    // Array of addresses of preinit fct
    PreInitArray,
    // Size in bytes of PreInitArray
    PreInitArraySize,
    // Address of SYMTAB_SHNDX section
    SymtabSectionHeadeIndex,
    // Versioning entry types
    GnuVerSym,
    GnuRelaCount,
    GnuRelCount,
    // State flags
    StateFlags,
    // Address of version definition table
    GnuVerDef,
    // Number of version definitions
    GnuVerDefNum,
    // Address of table with needed versions
    GnuVerNeed,
    // Number of needed versions
    GnuVerNeedNum,
    // GNU-style hash table
    GnuHashTable,
    Unknown(u64),
}

#[derive(Debug)]
struct DynamicSection {
    // This header is present if object file participates
    // in dynamic linking
    data: Vec<DynamicEntry>,
    strtab: StringTable,
}

#[derive(Debug)]
struct VersionNeed {
    // Version of structure
    version: u16,
    // Number of associated aux entries
    aux_count: u16,
    // Offset of filename in the dynstr section
    file_offset: u32,
    // Offset in bytes to vernaux array
    aux_offset: u32,
    // Offset in bytes to next VersionNeed entry, offset
    // is relative to version need section
    next_offset: u32,
}

#[derive(Debug)]
enum VersionNeedVersion {
    // No version
    None,
    // Current version
    Current,
    // Given version number
    Number,
    Unknown(u16),
}

#[derive(Debug)]
struct VersionAux {
    // Hash value of dependency name
    hash: u32,
    // Dependency specific information
    flags: VersionAuxFlags,
    // Unused
    other: u16,
    // Dependency name string offset
    name: u32,
    // Offset in bytes to next VersionAux
    next: u32,
}

#[derive(Debug)]
enum VersionAuxFlags {
    None,
    Weak,
    Unknown(u16),
}

#[derive(Debug)]
struct VersionSection {
    data: Vec<(Vec<VersionAux>, VersionNeed)>,
    // .dynamic string table used only for Display
    strtab: StringTable,
    // Name of the section acquired from sections strtab
    name: String,
}

impl ElfFileHeader {
    fn new(reader: &mut Cursor<Vec<u8>>) -> ElfFileHeader {
        // XXX: check magic
        let mut e_magic: [u8; 4] = [0; 4];
        reader.read_exact(&mut e_magic).unwrap();

        let e_class = FileClass::new(reader.read_u8().unwrap());
        let e_encoding = Encoding::new(reader.read_u8().unwrap());
        let e_version_ = reader.read_u8().unwrap();
        let e_os_abi = OsAbi::new(reader.read_u8().unwrap());
        let e_os_abi_version = reader.read_u8().unwrap();

        let mut e_padding_: [u8; 7] = [0; 7];
        reader.read_exact(&mut e_padding_).unwrap();

        let e_type = ObjectType::new(reader.read_u16::<LittleEndian>().unwrap());
        let e_machine = reader.read_u16::<LittleEndian>().unwrap();
        let e_version = Version::new(reader.read_u32::<LittleEndian>().unwrap());
        let e_entry = reader.read_u64::<LittleEndian>().unwrap();
        let e_phoff = reader.read_u64::<LittleEndian>().unwrap();
        let e_shoff = reader.read_u64::<LittleEndian>().unwrap();
        let e_flags = reader.read_u32::<LittleEndian>().unwrap();
        let e_ehsize = reader.read_u16::<LittleEndian>().unwrap();
        let e_phentsize = reader.read_u16::<LittleEndian>().unwrap();
        let e_phnum = reader.read_u16::<LittleEndian>().unwrap();
        let e_shentsize = reader.read_u16::<LittleEndian>().unwrap();
        let e_shnum = reader.read_u16::<LittleEndian>().unwrap();
        let e_shstrndx = reader.read_u16::<LittleEndian>().unwrap();

        ElfFileHeader {
            e_magic,
            e_class,
            e_encoding,
            e_version_,
            e_os_abi,
            e_os_abi_version,
            e_padding_,
            e_type,
            e_machine,
            e_version,
            e_entry,
            e_phoff,
            e_shoff,
            e_flags,
            e_ehsize,
            e_phentsize,
            e_phnum,
            e_shentsize,
            e_shnum,
            e_shstrndx,
        }
    }
}

impl FileClass {
    fn new(value: u8) -> FileClass {
        match value {
            0 => FileClass::None,
            1 => FileClass::ElfClass32,
            2 => FileClass::ElfClass64,
            _ => FileClass::Invalid(value),
        }
    }
}

impl Encoding {
    fn new(value: u8) -> Encoding {
        match value {
            0 => Encoding::None,
            1 => Encoding::LittleEndian,
            2 => Encoding::BigEndian,
            _ => Encoding::Invalid(value),
        }
    }
}

impl OsAbi {
    fn new(value: u8) -> OsAbi {
        use OsAbi::*;

        match value {
            0 => UnixVSystem,
            1 => HpUx,
            2 => NetBsd,
            3 => GnuElfExtensions,
            6 => SunSolaris,
            7 => IbmAix,
            8 => SgiIrix,
            9 => FreeBsd,
            10 => CompaqTru64Unix,
            11 => NovellModesto,
            12 => OpenBsd,
            64 => ArmEabi,
            97 => Arm,
            255 => Standalone,
            _ => OsAbi::Invalid(value),
        }
    }
}

impl ObjectType {
    fn new(value: u16) -> ObjectType {
        use ObjectType::*;

        match value {
            0 => NoFileType,
            1 => RelocatableFile,
            2 => ExecutableFile,
            3 => SharedObjectFile,
            4 => CoreFile,
            _ => Invalid(value),
        }
    }
}

impl Version {
    fn new(value: u32) -> Version {
        match value {
            0 => Version::Unspecified,
            1 => Version::Current,
            _ => Version::Invalid(value),
        }
    }
}

impl SectionHeader {
    fn new(reader: &mut Cursor<Vec<u8>>) -> SectionHeader {
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
    fn new(header: &ElfFileHeader, mut reader: &mut Cursor<Vec<u8>>) -> SectionHeaders {
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

    fn dynstr(&self, reader: &mut Cursor<Vec<u8>>) -> Option<StringTable> {
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

impl StringTable {
    // XXX: use some kind of buffer for this
    fn get(&self, offset: u64) -> String {
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

    fn empty() -> StringTable {
        StringTable { buffer: vec![] }
    }

    fn new(hdr: &SectionHeader, reader: &mut Cursor<Vec<u8>>) -> StringTable {
        reader.seek(SeekFrom::Start(hdr.sh_offset)).unwrap();

        let mut handle = reader.take(hdr.sh_size);
        let mut buffer: Vec<u8> = Vec::new();

        handle.read_to_end(&mut buffer).unwrap();

        StringTable { buffer }
    }
}

impl ProgramHeader {
    fn new(reader: &mut Cursor<Vec<u8>>) -> ProgramHeader {
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

impl ProgramHeaders {
    fn new(header: &ElfFileHeader, mut reader: &mut Cursor<Vec<u8>>) -> ProgramHeaders {
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

impl Symbol {
    fn new(reader: &mut Cursor<Vec<u8>>) -> Symbol {
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
    fn new(
        headers: &SectionHeaders,
        header: &SectionHeader,
        mut reader: &mut Cursor<Vec<u8>>,
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
            data: data,
            name: name,
            strtab: StringTable::new(&strtab, reader),
        }
    }
}

impl SymbolTables {
    fn new(headers: &SectionHeaders, reader: &mut Cursor<Vec<u8>>) -> SymbolTables {
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

impl Note {
    fn new(reader: &mut Cursor<Vec<u8>>) -> Note {
        let name_size = reader.read_u32::<LittleEndian>().unwrap();
        let desc_size = reader.read_u32::<LittleEndian>().unwrap();

        let type_ = reader.read_u32::<LittleEndian>().unwrap();

        let mut name_ = vec![0; name_size as usize];
        reader.read_exact(&mut name_).unwrap();

        let mut desc_ = vec![0; desc_size as usize];
        reader.read_exact(&mut desc_).unwrap();

        let name = String::from_utf8(name_).unwrap();
        let note_type = NoteType::new(type_);
        let desc = NoteDesc::new(&note_type, desc_);

        Note {
            name_size,
            desc_size,
            note_type,
            name,
            desc,
        }
    }
}

impl NoteType {
    fn new(value: u32) -> NoteType {
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
}

impl NoteDesc {
    fn new(value: &NoteType, data: Vec<u8>) -> NoteDesc {
        use NoteDesc::*;

        let asu32 = |index: usize| {
            (data[index + 3] as u32)
                | ((data[index + 2] as u32) << 8)
                | ((data[index + 1] as u32) << 16)
                | ((data[index] as u32) << 24)
        };

        match value {
            NoteType::ElfNoteAbi => ElfNoteAbi {
                os: NoteOs::new(data[0]),
                major: asu32(1),
                minor: asu32(5),
                patch: asu32(9),
            },
            NoteType::GnuHwCap => GnuHwCap(data),
            NoteType::GnuBuildID => GnuBuildID(to_hex_string(data)),
            NoteType::GnuGoldVersion => GnuGoldVersion(to_hex_string(data)),
            NoteType::GnuProperty => GnuProperty(data),
            _ => Unknown(data),
        }
    }
}

impl NoteOs {
    fn new(value: u8) -> NoteOs {
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
    // TODO: add new for ProgramHeaer
    fn new(header: &SectionHeader, name: String, mut reader: &mut Cursor<Vec<u8>>) -> NoteSection {
        reader.seek(SeekFrom::Start(header.sh_offset)).unwrap();

        let mut data = vec![];
        let mut i: u32 = 0;

        // XXX: use some better method for checking the end
        while i < header.sh_size as u32 {
            let note = Note::new(&mut reader);
            // 3 * 4 = 3 * uint32 = size of header
            i += 3 * 4 + note.name_size + note.desc_size;
            // last entry
            if note.name_size == 0 {
                break;
            }

            data.push(note);
        }

        NoteSection {
            data: data,
            name: name,
        }
    }
}

impl NoteSections {
    fn new(headers: &SectionHeaders, reader: &mut Cursor<Vec<u8>>) -> NoteSections {
        let mut data: Vec<NoteSection> = vec![];

        for header in &headers.headers {
            if header.sh_type == SectionHeaderType::Note {
                let name = headers.strtab.get(header.sh_name as u64);
                data.push(NoteSection::new(&header, name, reader));
            }
        }

        NoteSections { data }
    }
}

impl Interpret {
    fn new(headers: &ProgramHeaders, reader: &mut Cursor<Vec<u8>>) -> Interpret {
        let mut path = String::from("");

        for header in &headers.headers {
            if header.p_type != SegmentType::Interp {
                continue;
            }

            reader.seek(SeekFrom::Start(header.p_offset)).unwrap();

            let mut data = vec![0; header.p_filesz as usize];
            reader.read_exact(&mut data).unwrap();

            path = String::from_utf8(data).unwrap();
            break;
        }

        Interpret { path }
    }
}

impl DynamicEntry {
    fn new(reader: &mut Cursor<Vec<u8>>) -> DynamicEntry {
        let tag = DynamicEntryTag::new(reader.read_u64::<LittleEndian>().unwrap());
        let value = reader.read_u64::<LittleEndian>().unwrap();

        DynamicEntry { tag, value }
    }
}

impl DynamicEntryTag {
    fn new(value: u64) -> DynamicEntryTag {
        use DynamicEntryTag::*;

        match value {
            0 => Null,
            1 => Needed,
            2 => PltRelocsSize,
            3 => PltGot,
            4 => Hash,
            5 => Strtab,
            6 => Symtab,
            7 => Rela,
            8 => RelaSize,
            9 => RelaEntSize,
            10 => StrtabSize,
            11 => SymtabEntSize,
            12 => Init,
            13 => Fini,
            14 => SoName,
            15 => Rpath,
            16 => Symbolic,
            17 => Rel,
            18 => RelSize,
            19 => RelEntSize,
            20 => PltRel,
            21 => Debug,
            22 => TextRel,
            23 => JmpRel,
            24 => BindNow,
            25 => InitArray,
            26 => FiniArray,
            27 => InitiArraySize,
            28 => FiniArraySize,
            29 => RunPath,
            30 => Flags,
            31 => Encoding,
            32 => PreInitArray,
            33 => PreInitArraySize,
            34 => SymtabSectionHeadeIndex,
            0x6ffffff0 => GnuVerSym,
            0x6ffffff9 => GnuRelaCount,
            0x6ffffffa => GnuRelCount,
            0x6ffffffb => StateFlags,
            0x6ffffffc => GnuVerDef,
            0x6ffffffd => GnuVerDefNum,
            0x6ffffffe => GnuVerNeed,
            0x6fffffff => GnuVerNeedNum,
            0x6ffffef5 => GnuHashTable,
            _ => Unknown(value),
        }
    }
}

impl DynamicSection {
    fn new(headers: &SectionHeaders, mut reader: &mut Cursor<Vec<u8>>) -> DynamicSection {
        // XXX: refactor this shit
        // lets find dyamic section header
        let mut header: Option<&SectionHeader> = None;

        for hdr in &headers.headers {
            if hdr.sh_type == SectionHeaderType::Dynamic {
                header = Some(hdr);
                break;
            }
        }

        if header.is_none() {
            return DynamicSection {
                strtab: StringTable::empty(),
                data: vec![],
            };
        }

        let header = header.unwrap();

        reader.seek(SeekFrom::Start(header.sh_offset)).unwrap();
        // read all dyn entries and string table address and size
        let mut entries: Vec<DynamicEntry> = vec![];
        let mut strtab_addr = 0;
        let mut strtab_size = 0;

        loop {
            let entry = DynamicEntry::new(reader);

            if entry.tag == DynamicEntryTag::Null {
                entries.push(entry);
                break;
            } else if entry.tag == DynamicEntryTag::Strtab {
                strtab_addr = entry.value;
            } else if entry.tag == DynamicEntryTag::StrtabSize {
                strtab_size = entry.value;
            }
            entries.push(entry);
        }

        // XXX: we should compute file addr from strtab addr (it's
        //      vma) but for that we need program headers
        let mut strtab = StringTable::empty();

        for hdr in &headers.headers {
            if hdr.sh_type != SectionHeaderType::Strtab {
                continue;
            }

            if hdr.sh_addr == strtab_addr && hdr.sh_size == strtab_size {
                strtab = StringTable::new(&hdr, &mut reader);
            }
            break;
        }

        DynamicSection {
            strtab: strtab,
            data: entries,
        }
    }
}

impl VersionNeed {
    fn new(reader: &mut Cursor<Vec<u8>>) -> VersionNeed {
        VersionNeed {
            version: reader.read_u16::<LittleEndian>().unwrap(),
            aux_count: reader.read_u16::<LittleEndian>().unwrap(),
            file_offset: reader.read_u32::<LittleEndian>().unwrap(),
            aux_offset: reader.read_u32::<LittleEndian>().unwrap(),
            next_offset: reader.read_u32::<LittleEndian>().unwrap(),
        }
    }
}

impl VersionSection {
    fn new(headers: &SectionHeaders, reader: &mut Cursor<Vec<u8>>) -> Option<VersionSection> {
        let mut header: Option<&SectionHeader> = None;

        for hdr in &headers.headers {
            if hdr.sh_type == SectionHeaderType::GnuVerNeed {
                header = Some(hdr);
                break;
            }
        }

        if header.is_none() {
            return None;
        }

        let header = header.unwrap();
        let mut offset: u64 = 0;
        let mut data: Vec<(Vec<VersionAux>, VersionNeed)> = vec![];
        let mut aux: Vec<VersionAux> = vec![];

        let mut cnt = 0;

        while cnt < header.sh_info {
            reader
                .seek(SeekFrom::Start(header.sh_offset + offset))
                .unwrap();

            let verneed = VersionNeed::new(reader);
            let mut aux_offset: u64 = verneed.aux_offset as u64;
            let mut i = 0;

            while i < verneed.aux_count {
                reader
                    .seek(SeekFrom::Start(header.sh_offset + offset + aux_offset))
                    .unwrap();

                let au = VersionAux::new(reader);

                aux_offset += au.next as u64;
                aux.push(au);
                i += 1;
            }

            offset += verneed.next_offset as u64;
            data.push((aux, verneed));
            aux = vec![];

            cnt += 1;
        }

        let strtab = headers.dynstr(reader).unwrap();
        let name = headers.strtab.get(header.sh_name as u64);

        Some(VersionSection { data, strtab, name })
    }
}
impl VersionAux {
    fn new(reader: &mut Cursor<Vec<u8>>) -> VersionAux {
        VersionAux {
            hash: reader.read_u32::<LittleEndian>().unwrap(),
            flags: VersionAuxFlags::new(reader.read_u16::<LittleEndian>().unwrap()),
            other: reader.read_u16::<LittleEndian>().unwrap(),
            name: reader.read_u32::<LittleEndian>().unwrap(),
            next: reader.read_u32::<LittleEndian>().unwrap(),
        }
    }
}

impl VersionAuxFlags {
    fn new(value: u16) -> VersionAuxFlags {
        match value {
            0x0 => VersionAuxFlags::None,
            0x2 => VersionAuxFlags::Weak,
            _ => VersionAuxFlags::Unknown(value),
        }
    }
}

impl fmt::Display for VersionSection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(
            f,
            "Version needs section `{}' contain {} entries",
            self.name,
            self.data.len()
        )?;

        for (auxes, verneed) in &self.data {
            let file = self.strtab.get(verneed.file_offset as u64);

            writeln!(
                f,
                "Version: {:<4} File: {:<16} AuxCount: {:<4}",
                verneed.version, file, verneed.aux_count
            )?;

            for aux in auxes {
                let name = self.strtab.get(aux.name as u64);

                writeln!(
                    f,
                    "    Version: {:<4} Name: {:<16} Flags: {:?} Hash: {:#08x}",
                    aux.other, name, aux.flags, aux.hash
                )?;
            }
        }

        Ok(())
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
            writeln!(f, "{}", format!("{:?}", note.desc))?;
        }

        writeln!(f, "")?;

        Ok(())
    }
}

impl fmt::Display for DynamicSection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Dynamic section contains {} entries:", self.data.len())?;
        writeln!(f, "{:<32} Name/Value", "Tag")?;

        for entry in &self.data {
            write!(f, "{:<32} {:<4}", format!("{:?}", entry.tag), entry.value)?;

            if entry.tag == DynamicEntryTag::Needed {
                let name = self.strtab.get(entry.value);
                write!(f, " ({})", name)?;
            }

            writeln!(f, "")?;
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

impl fmt::Display for ElfFileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Elf Header:")?;

        writeln!(f, "{:<32}{:x?}", "Magic:", self.e_magic)?;
        writeln!(f, "{:<32}{:?}", "Class:", self.e_class)?;
        writeln!(f, "{:<32}{:?}", "Encoding:", self.e_encoding)?;
        writeln!(f, "{:<32}{:?}", "OS/ABI:", self.e_os_abi)?;
        writeln!(f, "{:<32}{}", "ABI Version:", self.e_os_abi_version)?;
        writeln!(f, "{:<32}{:x?}", "Padding:", self.e_padding_)?;
        writeln!(f, "{:<32}{:?}", "Type:", self.e_type)?;
        writeln!(f, "{:<32}{}", "Architecture:", show_machine(self.e_machine))?;
        writeln!(f, "{:<32}{:?}", "Version:", self.e_version)?;
        writeln!(f, "{:<32}{:#x}", "Entry point address:", self.e_entry)?;
        writeln!(f, "{:<32}{}", "Program header offset:", self.e_phoff)?;
        writeln!(f, "{:<32}{}", "Section header offset:", self.e_shoff)?;
        writeln!(f, "{:<32}{}", "Flags:", self.e_flags)?;
        writeln!(f, "{:<32}{}", "Size of this header:", self.e_ehsize)?;
        writeln!(f, "{:<32}{}", "Size of program headers:", self.e_phentsize)?;
        writeln!(f, "{:<32}{}", "Number of program headers:", self.e_phnum)?;
        writeln!(f, "{:<32}{}", "Size of section headers:", self.e_shentsize)?;
        writeln!(f, "{:<32}{}", "Number of section headers:", self.e_shnum)?;
        writeln!(
            f,
            "{:<32}{}",
            "Section header strtab index:", self.e_shstrndx
        )
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
            "{:<6} {:<16} {:<8} {:<8} {:<6} {:<9} {:<3} {}",
            "Num", "Value", "Size", "Type", "Bind", "Vis", "Ndx", "Name"
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

impl fmt::Display for SymbolTables {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut result = Ok(());

        for symtab in &self.data {
            result = symtab.fmt(f);
            writeln!(f, "")?;
        }
        result
    }
}

impl fmt::Display for Interpret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Interpret path: `{}'", self.path)
    }
}

fn show_machine(value: u16) -> &'static str {
    match value {
        0 => "No machine",
        1 => "AT&T WE 32100",
        2 => "SUN SPARC",
        3 => "Intel 80386",
        4 => "Motorola m68k family",
        5 => "Motorola m88k family",
        6 => "Intel MCU",
        7 => "Intel 80860",
        8 => "MIPS R3000 big-endian",
        9 => "IBM System/370",
        10 => "MIPS R3000 little-endian",
        15 => "HPPA",
        16 => "reserved 16",
        17 => "Fujitsu VPP500",
        18 => "Sun's v8plus",
        19 => "Intel 80960",
        20 => "PowerPC",
        21 => "PowerPC 64-bit",
        22 => "IBM S390",
        23 => "IBM SPU/SPC",
        36 => "NEC V800 series",
        37 => "Fujitsu FR20",
        38 => "TRW RH-32",
        39 => "Motorola RCE",
        40 => "ARM",
        41 => "Digital Alpha",
        42 => "Hitachi SH",
        43 => "SPARC v9 64-bit",
        44 => "Siemens Tricore",
        45 => "Argonaut RISC Core",
        46 => "Hitachi H8/300",
        47 => "Hitachi H8/300H",
        48 => "Hitachi H8S",
        49 => "Hitachi H8/500",
        50 => "Intel Merced",
        51 => "Stanford MIPS-X",
        52 => "Motorola Coldfire",
        53 => "Motorola M68HC12",
        54 => "Fujitsu MMA Multimedia Accelerator",
        55 => "Siemens PCP",
        56 => "Sony nCPU embeeded RISC",
        57 => "Denso NDR1 microprocessor",
        58 => "Motorola Start*Core processor",
        59 => "Toyota ME16 processor",
        60 => "STMicroelectronic ST100 processor",
        61 => "Advanced Logic Corp. Tinyj emb.fam",
        62 => "AMD x86-64 architecture",
        63 => "Sony DSP Processor",
        64 => "Digital PDP-10",
        65 => "Digital PDP-11",
        66 => "Siemens FX66 microcontroller",
        67 => "STMicroelectronics ST9+ 8/16 mc",
        68 => "STmicroelectronics ST7 8 bit mc",
        69 => "Motorola MC68HC16 microcontroller",
        70 => "Motorola MC68HC11 microcontroller",
        71 => "Motorola MC68HC08 microcontroller",
        72 => "Motorola MC68HC05 microcontroller",
        73 => "Silicon Graphics SVx",
        74 => "STMicroelectronics ST19 8 bit mc",
        75 => "Digital VAX",
        76 => "Axis Communications 32-bit emb.proc",
        77 => "Infineon Technologies 32-bit emb.proc",
        78 => "Element 14 64-bit DSP Processor",
        79 => "LSI Logic 16-bit DSP Processor",
        80 => "Donald Knuth's educational 64-bit proc",
        81 => "Harvard University machine-independent object files",
        82 => "SiTera Prism",
        83 => "Atmel AVR 8-bit microcontroller",
        84 => "Fujitsu FR30",
        85 => "Mitsubishi D10V",
        86 => "Mitsubishi D30V",
        87 => "NEC v850",
        88 => "Mitsubishi M32R",
        89 => "Matsushita MN10300",
        90 => "Matsushita MN10200",
        91 => "picoJava",
        92 => "OpenRISC 32-bit embedded processor",
        93 => "ARC International ARCompact",
        94 => "Tensilica Xtensa Architecture",
        95 => "Alphamosaic VideoCore",
        96 => "Thompson Multimedia General Purpose Proc",
        97 => "National Semi. 32000",
        98 => "Tenor Network TPC",
        99 => "Trebia SNP 1000",
        100 => "STMicroelectronics ST200",
        101 => "Ubicom IP2xxx",
        102 => "MAX processor",
        103 => "National Semi. CompactRISC",
        104 => "Fujitsu F2MC16",
        105 => "Texas Instruments msp430",
        106 => "Analog Devices Blackfin DSP",
        107 => "Seiko Epson S1C33 family",
        108 => "Sharp embedded microprocessor",
        109 => "Arca RISC",
        110 => "PKU-Unity & MPRC Peking Uni. mc series",
        111 => "eXcess configurable cpu",
        112 => "Icera Semi. Deep Execution Processor",
        113 => "Altera Nios II",
        114 => "National Semi. CompactRISC CRX",
        115 => "Motorola XGATE",
        116 => "Infineon C16x/XC16x",
        117 => "Renesas M16C",
        118 => "Microchip Technology dsPIC30F",
        119 => "Freescale Communication Engine RISC",
        120 => "Renesas M32C",
        131 => "Altium TSK3000",
        132 => "Freescale RS08",
        133 => "Analog Devices SHARC family",
        134 => "Cyan Technology eCOG2",
        135 => "Sunplus S+core7 RISC",
        136 => "New Japan Radio (NJR) 24-bit DSP",
        137 => "Broadcom VideoCore III",
        138 => "RISC for Lattice FPGA",
        139 => "Seiko Epson C17",
        140 => "Texas Instruments TMS320C6000 DSP",
        141 => "Texas Instruments TMS320C2000 DSP",
        142 => "Texas Instruments TMS320C55x DSP",
        143 => "Texas Instruments App. Specific RISC",
        144 => "Texas Instruments Prog. Realtime Unit",
        160 => "STMicroelectronics 64bit VLIW DSP",
        161 => "Cypress M8C",
        162 => "Renesas R32C",
        163 => "NXP Semi. TriMedia",
        164 => "QUALCOMM DSP6",
        165 => "Intel 8051 and variants",
        166 => "STMicroelectronics STxP7x",
        167 => "Andes Tech. compact code emb. RISC",
        168 => "Cyan Technology eCOG1X",
        169 => "Dallas Semi. MAXQ30 mc",
        170 => "New Japan Radio (NJR) 16-bit DSP",
        171 => "M2000 Reconfigurable RISC",
        172 => "Cray NV2 vector architecture",
        173 => "Renesas RX",
        174 => "Imagination Tech. META",
        175 => "MCST Elbrus",
        176 => "Cyan Technology eCOG16",
        177 => "National Semi. CompactRISC CR16",
        178 => "Freescale Extended Time Processing Unit",
        179 => "Infineon Tech. SLE9X",
        180 => "Intel L10M",
        181 => "Intel K10M",
        182 => "reserved 182",
        183 => "ARM AARCH64",
        184 => "reserved 184",
        185 => "Amtel 32-bit microprocessor",
        186 => "STMicroelectronics STM8",
        187 => "Tileta TILE64",
        188 => "Tilera TILEPro",
        189 => "Xilinx MicroBlaze",
        190 => "NVIDIA CUDA",
        191 => "Tilera TILE-Gx",
        192 => "CloudShield",
        193 => "KIPO-KAIST Core-A 1st gen.",
        194 => "KIPO-KAIST Core-A 2nd gen.",
        195 => "Synopsys ARCompact V2",
        196 => "Open8 RISC",
        197 => "Renesas RL78",
        198 => "Broadcom VideoCore V",
        199 => "Renesas 78KOR",
        200 => "Freescale 56800EX DSC",
        201 => "Beyond BA1",
        202 => "Beyond BA2",
        203 => "XMOS xCORE",
        204 => "Microchip 8-bit PIC(r)",
        210 => "KM211 KM32",
        211 => "KM211 KMX32",
        212 => "KM211 KMX16",
        213 => "KM211 KMX8",
        214 => "KM211 KVARC",
        215 => "Paneve CDP",
        216 => "Cognitive Smart Memory Processor",
        217 => "Bluechip CoolEngine",
        218 => "Nanoradio Optimized RISC",
        219 => "CSR Kalimba",
        220 => "Zilog Z80",
        221 => "Controls and Data Services VISIUMcore",
        222 => "FTDI Chip FT32",
        223 => "Moxie processor",
        224 => "AMD GPU",
        243 => "RISC-V",
        247 => "Linux BPF -- in-kernel virtual machine",
        _ => "Unknown",
    }
}

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

fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join(" ")
}

struct DisplayOptions {
    file_header: bool,
    program_headers: bool,
    section_headers: bool,
    symbols: bool,
    notes: bool,
    dynamic: bool,
    version_info: bool,
    interpret: bool,
}

fn main() {
    use std::fs::File;

    let matches = clap_app!(readelf =>
        (version: "0.8")
        (author: "Adam S. <adam.stepan@firma.seznam.cz>")
        (about: "Displays information about ELF files")
        (@arg all: -a --all "Equivalent to: -h -l -S -s -d -V -i")
        (@arg ("file-header"): -h --("file-header") "Display the ELF file header")
        (@arg interpret: -i --interpret "Display data of .interp section")
        (@arg ("program-headers"): -l --("program-headers") "Display the program headers")
        (@arg ("section-headers"): -S --("section-headers") "Display the sections' header")
        (@arg symbols: -s --("symbols") "Display the symbol table")
        (@arg notes: --notes "Display notes")
        (@arg dynamic: -d --dynamic "Display the dynamic section")
        (@arg ("version-info"): -V --("version-info") "Display the version sections")
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
    };

    file.read_to_end(&mut buffer).unwrap();

    let mut reader = Cursor::new(buffer);

    let fh = ElfFileHeader::new(&mut reader);
    let ph = ProgramHeaders::new(&fh, &mut reader);
    let sh = SectionHeaders::new(&fh, &mut reader);
    let st = SymbolTables::new(&sh, &mut reader);
    let ns = NoteSections::new(&sh, &mut reader);
    let ip = Interpret::new(&ph, &mut reader);
    let dy = DynamicSection::new(&sh, &mut reader);
    let vs = VersionSection::new(&sh, &mut reader).unwrap();

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
        println!("{}", ip);
    }

    if display.symbols {
        println!("{}", st);
    }

    if display.notes {
        println!("{}", ns);
    }

    if display.dynamic {
        println!("{}", dy);
    }

    if display.version_info {
        println!("{}", vs);
    }
}
