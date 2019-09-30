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
    magic: [u8; 4],
    class: FileClass,
    encoding: Encoding,
    version_: u8, // XXX: must be EV_CURRENT
    os_abi: OsAbi,
    abi_version: u8,
    padding: [u8; 7],

    object_type: ObjectType,
    architecture: u16, // XXX: use enum for this
    version: Version,
    entry_point_address: u64,
    program_header_offset: u64,
    section_header_offset: u64,
    flags: u32,
    size: u16,
}

impl ElfFileHeader {
    fn new(buffer: &Vec<u8>) -> ElfFileHeader {
        let mut reader = Cursor::new(buffer);

        let mut header = ElfFileHeader {
            magic: [0; 4],
            class: FileClass::ElfClass64,
            encoding: Encoding::None,
            version_: 0,
            os_abi: OsAbi::HpUx,
            abi_version: 0,
            padding: [0; 7],

            object_type: ObjectType::NoFileType,
            architecture: 0,
            version: Version::Unspecified,
            entry_point_address: 0,
            program_header_offset: 0,
            section_header_offset: 0,
            flags: 0,
            size: 0,
        };

        // XXX: check magic
        reader.read_exact(&mut header.magic).unwrap();

        header.class = FileClass::new(reader.read_u8().unwrap());
        header.encoding = Encoding::new(reader.read_u8().unwrap());
        header.version_ = reader.read_u8().unwrap();
        header.os_abi = OsAbi::new(reader.read_u8().unwrap());
        header.abi_version = reader.read_u8().unwrap();
        reader.read_exact(&mut header.padding).unwrap();

        header.object_type = ObjectType::new(reader.read_u16::<LittleEndian>().unwrap());
        header.architecture = reader.read_u16::<LittleEndian>().unwrap();
        header.version = Version::new(reader.read_u32::<LittleEndian>().unwrap());
        header.entry_point_address = reader.read_u64::<LittleEndian>().unwrap();
        header.program_header_offset = reader.read_u64::<LittleEndian>().unwrap();
        header.section_header_offset = reader.read_u64::<LittleEndian>().unwrap();
        header.flags = reader.read_u32::<LittleEndian>().unwrap();
        header.size = reader.read_u16::<LittleEndian>().unwrap();

        return header;
    }
}

impl fmt::Display for ElfFileHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Elf Header:")?;
        writeln!(f, "Magic:\t\t\t{:x?}", self.magic)?;
        writeln!(f, "Class:\t\t\t{:?}", self.class)?;
        writeln!(f, "Encoding:\t\t{:?}", self.encoding)?;
        writeln!(f, "OS/ABI:\t\t\t{:?}", self.os_abi)?;
        writeln!(f, "ABI Version:\t\t{}", self.abi_version)?;
        writeln!(f, "Padding: \t\t{:x?}", self.padding)?;
        writeln!(f, "Type:\t\t\t{:?}", self.object_type)?;
        writeln!(f, "Architecture:\t\t{:?}", self.architecture)?;
        writeln!(f, "Version:\t\t{:?}", self.version)?;
        writeln!(f, "Entry point address:\t{:#x}", self.entry_point_address)?;
        writeln!(f, "Program header offset:\t{}", self.program_header_offset)?;
        writeln!(f, "Section header offset:\t{}", self.section_header_offset)?;
        writeln!(f, "Flags:\t\t\t{}", self.flags)?;
        writeln!(f, "Size of this header:\t{}", self.size)
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
