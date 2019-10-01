use byteorder::{LittleEndian, ReadBytesExt};
use std::fmt;
use std::io::prelude::*;
use std::io::Cursor;

#[derive(Debug)]
enum ObjectType {
    NoFileType,
    RelocatableFile,
    ExecutableFile,
    SharedObjectFile,
    CoreFile,
    Invalid(u16), // XXX: omit ranges for now
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

#[derive(Debug)]
enum Version {
    Unspecified,
    Current,
    Invalid(u32),
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

#[derive(Debug)]
enum FileClass {
    None,
    ElfClass32,
    ElfClass64,
    Invalid(u8),
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

#[derive(Debug)]
enum Encoding {
    None,
    LittleEndian,
    BigEndian,
    Invalid(u8),
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

#[derive(Debug)]
enum OsAbi {
    UnixVSystem,
    HpUx,
    NetBsd,
    GnuElfExtensions,
    SunSolaris,
    IbmAix,
    SgiIrix,
    FreeBsd,
    CompaqTru64Unix,
    NovellModesto,
    OpenBsd,
    ArmEabi,
    Arm,
    Standalone,
    Invalid(u8),
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

impl ElfFileHeader {
    fn new(buffer: &Vec<u8>) -> ElfFileHeader {
        let mut reader = Cursor::new(buffer);

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

#[derive(Debug)]
enum SectionHeaderType {
    // Section header table entry unused
    Null,
    // Program data
    Progbits,
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
}

struct SectionHeader {
    // Section name (string tbl index)
    sh_name: u32,
    // Section type
    sh_type: u32,
    // Section flags
    sh_flags: u64,
    // Sectuin virtual address at execution
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
    sh_entisize: u64,
}

impl fmt::Display for ElfFileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Elf Header:")?;
        writeln!(f, "Magic:\t\t\t\t{:x?}", self.e_magic)?;
        writeln!(f, "Class:\t\t\t\t{:?}", self.e_class)?;
        writeln!(f, "Encoding:\t\t\t{:?}", self.e_encoding)?;
        writeln!(f, "OS/ABI:\t\t\t\t{:?}", self.e_os_abi)?;
        writeln!(f, "ABI Version:\t\t\t{}", self.e_os_abi_version)?;
        writeln!(f, "Padding: \t\t\t{:x?}", self.e_padding_)?;
        writeln!(f, "Type:\t\t\t\t{:?}", self.e_type)?;
        writeln!(f, "Architecture:\t\t\t{:?}", self.e_machine)?;
        writeln!(f, "Version:\t\t\t{:?}", self.e_version)?;
        writeln!(f, "Entry point address:\t\t{:#x}", self.e_entry)?;
        writeln!(f, "Program header offset:\t\t{}", self.e_phoff)?;
        writeln!(f, "Section header offset:\t\t{}", self.e_shoff)?;
        writeln!(f, "Flags:\t\t\t\t{}", self.e_flags)?;
        writeln!(f, "Size of this header:\t\t{}", self.e_ehsize)?;
        writeln!(f, "Size of program headers:\t{}", self.e_phentsize)?;
        writeln!(f, "Number of program headers:\t{}", self.e_phnum)?;
        writeln!(f, "Size of section headers:\t{}", self.e_shentsize)?;
        writeln!(f, "Number of section headers:\t{}", self.e_shnum)?;
        writeln!(f, "Section header strtab index:\t{}", self.e_shstrndx)
    }
}

fn main() {
    use std::env;
    use std::fs::File;
    use std::process;

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("usage: rustelf <binary>");
        process::exit(1);
    }

    let filename = &args[1];

    let mut file = File::open(filename).unwrap();
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer).unwrap();

    let fh = ElfFileHeader::new(&mut buffer);

    println!("{}", fh);
}
