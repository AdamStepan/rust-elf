use crate::reader::{LittleEndian, ReadBytesExt, Reader};
use std::fmt;
use std::io::Read;
use thiserror::Error;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

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
#[derive(Debug)]
pub enum FileClass {
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
pub enum Encoding {
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
pub enum OsAbi {
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
pub enum ObjectType {
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
pub enum Version {
    // Invalid ELF version
    Unspecified,
    // Current version
    Current,
    // Unknown
    Invalid(u32),
}

#[derive(Debug)]
pub struct ElfFileHeader {
    // Conglomeration of the identification bytes, must be \177ELF
    pub e_magic: [u8; 4],
    // Filpub e class
    pub e_class: FileClass,
    // Data pub encoding
    pub e_encoding: Encoding,
    // Filpub e version, value must be EV_CURRENT
    pub e_version_: u8,
    // OS ABI idpub entification
    pub e_os_abi: OsAbi,
    // ABI vpub ersion
    pub e_os_abi_version: u8,
    // Padding bytpub es
    pub e_padding_: [u8; 7],
    // Objpub ect file type
    pub e_type: ObjectType,
    // Architpub ecture
    pub e_machine: u16,
    // Objpub ect file version
    pub e_version: Version,
    // Entry point virtual addrpub ess
    pub e_entry: u64,
    // Program hpub eader table file offset
    pub e_phoff: u64,
    // Spub ection header table file offset
    pub e_shoff: u64,
    // Procpub essor-specific flags
    pub e_flags: u32,
    // ELF hpub eader size in bytes
    pub e_ehsize: u16,
    // Program hpub eader table entry size
    pub e_phentsize: u16,
    // Program hpub eader table entry count
    pub e_phnum: u16,
    // Spub ection header table entry size
    pub e_shentsize: u16,
    // Spub ection header table entry count
    pub e_shnum: u16,
    // Spub ection header string table index
    pub e_shstrndx: u16,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Elf magic mismatch: got: {:02X?}, expected: {:02X?}", magic, ELF_MAGIC)]
    ElfMagicMismatchError {
        magic: [u8; 4]
    },

    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

impl ElfFileHeader {
    pub fn new(reader: &mut Reader) -> Result<ElfFileHeader, Error> {
        let mut e_magic: [u8; 4] = [0; 4];
        reader.read_exact(&mut e_magic)?;

        if e_magic[0] != ELF_MAGIC[0]
            || e_magic[1] != ELF_MAGIC[1]
            || e_magic[2] != ELF_MAGIC[2]
            || e_magic[3] != ELF_MAGIC[3]
        {
            return Err(Error::ElfMagicMismatchError { magic: e_magic });
        }

        let e_class = FileClass::new(reader.read_u8()?);
        let e_encoding = Encoding::new(reader.read_u8()?);
        let e_version_ = reader.read_u8()?;
        let e_os_abi = OsAbi::new(reader.read_u8()?);
        let e_os_abi_version = reader.read_u8()?;

        let mut e_padding_: [u8; 7] = [0; 7];
        reader.read_exact(&mut e_padding_)?;

        let e_type = ObjectType::new(reader.read_u16::<LittleEndian>()?);
        let e_machine = reader.read_u16::<LittleEndian>()?;
        let e_version = Version::new(reader.read_u32::<LittleEndian>()?);
        let e_entry = reader.read_u64::<LittleEndian>()?;
        let e_phoff = reader.read_u64::<LittleEndian>()?;
        let e_shoff = reader.read_u64::<LittleEndian>()?;
        let e_flags = reader.read_u32::<LittleEndian>()?;
        let e_ehsize = reader.read_u16::<LittleEndian>()?;
        let e_phentsize = reader.read_u16::<LittleEndian>()?;
        let e_phnum = reader.read_u16::<LittleEndian>()?;
        let e_shentsize = reader.read_u16::<LittleEndian>()?;
        let e_shnum = reader.read_u16::<LittleEndian>()?;
        let e_shstrndx = reader.read_u16::<LittleEndian>()?;

        Ok(ElfFileHeader {
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
        })
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
