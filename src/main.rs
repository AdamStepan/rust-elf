use byteorder::{LittleEndian, ReadBytesExt};
use std::fmt;
use std::io::prelude::*;
use std::io::{Cursor, SeekFrom};

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

#[derive(Debug, PartialEq)]
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
    // GVersion symbol table
    GnuVerSym,
    Unknown(u32),
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

#[derive(Debug)]
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

#[derive(Debug)]
struct SectionHeaders {
    headers: Vec<SectionHeader>,
    strtab: StringTable,
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

#[derive(Debug)]
struct StringTable {
    // XXX: we cannot use map with offsets, because some sections
    //      point to the middle of another string
    buffer: Vec<u8>,
}

#[derive(Debug)]
struct Symbol {
    // Symbol name (string tbl index)
    st_name: u32,
    // Symbol type and binding
    // XXX: use st_bind and st_type
    st_info: u8,
    // Symbol visibility
    st_other: u8,
    // Section index
    st_shndx: u16,
    // Symbol value
    st_value: u64,
    // Symbol size
    st_size: u64,
}

impl Symbol {
    fn new(mut reader: &mut Cursor<Vec<u8>>) -> Symbol {
        Symbol {
            st_name: reader.read_u32::<LittleEndian>().unwrap(),
            st_info: reader.read_u8().unwrap(),
            st_other: reader.read_u8().unwrap(),
            st_shndx: reader.read_u16::<LittleEndian>().unwrap(),
            st_value: reader.read_u64::<LittleEndian>().unwrap(),
            st_size: reader.read_u64::<LittleEndian>().unwrap(),
        }
    }
}

#[derive(Debug)]
enum SymbolBind {
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

impl SymbolBind {
    fn new(info: u8) -> SymbolBind {
        use SymbolBind::*;

        match info >> 4 {
            0 => Local,
            1 => Global,
            2 => Weak,
            10 => GnuUnique,
            _ => Unknown(info >> 4),
        }
    }
}

#[derive(Debug)]
struct SymbolTable {
    data: Vec<Symbol>,
    strtab: StringTable,
    name: String,
}

use std::mem;

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
            i += mem::size_of::<Symbol>() as u64;
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

#[derive(Debug)]
struct SymbolTables {
    data: Vec<SymbolTable>,
}

impl SymbolTables {
    fn new(headers: &SectionHeaders, mut reader: &mut Cursor<Vec<u8>>) -> SymbolTables {
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

    fn new(hdr: &SectionHeader, reader: &mut Cursor<Vec<u8>>) -> StringTable {
        // XXX: check type of section header

        reader.seek(SeekFrom::Start(hdr.sh_offset)).unwrap();

        let mut handle = reader.take(hdr.sh_size);
        let mut buffer: Vec<u8> = Vec::new();

        handle.read_to_end(&mut buffer).unwrap();

        StringTable { buffer }
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

        let strtab = StringTable::new(&headers[header.e_shstrndx as usize], &mut reader);

        SectionHeaders { headers, strtab }
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
struct ProgramHeaders {
    headers: Vec<ProgramHeader>,
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
        writeln!(f, "Architecture:\t\t\t{}", show_machine(self.e_machine))?;
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

    let mut reader = Cursor::new(buffer);

    let fh = ElfFileHeader::new(&mut reader);
    let ph = ProgramHeaders::new(&fh, &mut reader);
    let sh = SectionHeaders::new(&fh, &mut reader);
    let st = SymbolTables::new(&sh, &mut reader);

    println!("{}", fh);
    println!("{}", ph);
    println!("{}", sh);
    println!("{:?}", st);
}
