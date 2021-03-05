use crate::reader::{LittleEndian, ReadBytesExt, Reader, Seek, SeekFrom};
use crate::section::{SectionHeaderType, SectionHeaders};
use crate::symbols::StringTable;
use std::fmt;

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
pub struct DynamicSection {
    // This header is present if object file participates
    // in dynamic linking
    data: Vec<DynamicEntry>,
    strtab: StringTable,
}

impl DynamicEntry {
    fn new(reader: &mut Reader) -> DynamicEntry {
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
    pub fn new(headers: &SectionHeaders, mut reader: &mut Reader) -> Option<DynamicSection> {
        let header = headers.get(SectionHeaderType::Dynamic)?;

        reader.seek(SeekFrom::Start(header.sh_offset)).unwrap();
        // read all dyn entries and string table address and size
        let mut entries: Vec<DynamicEntry> = vec![];

        // read entries until you get DT_NULL terminator
        loop {
            let entry = DynamicEntry::new(reader);

            entries.push(entry);

            if entries.last().unwrap().tag == DynamicEntryTag::Null {
                break;
            }
        }

        let strtab_header = headers.get_by_index(header.sh_link as usize);
        let strtab = StringTable::new(&strtab_header, &mut reader);

        Some(DynamicSection {
            strtab: strtab,
            data: entries,
        })
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
