use crate::reader::{LittleEndian, ReadBytesExt, Reader, Seek, SeekFrom};
use crate::section::{SectionHeaderType, SectionHeaders};
use crate::symbols::StringTable;
use anyhow::{Result, Context};
use std::fmt;

#[derive(Debug)]
pub struct VersionNeed {
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
pub struct VersionAux {
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
pub enum VersionAuxFlags {
    None,
    Weak,
    Unknown(u16),
}

#[derive(Debug)]
pub struct VersionSection {
    data: Vec<(Vec<VersionAux>, VersionNeed)>,
    // .dynamic string table used only for Display
    strtab: StringTable,
    // Name of the section acquired from sections strtab
    name: String,
}

impl VersionNeed {
    fn new(reader: &mut Reader) -> Result<VersionNeed> {
        Ok(VersionNeed {
            version: reader.read_u16::<LittleEndian>()?,
            aux_count: reader.read_u16::<LittleEndian>()?,
            file_offset: reader.read_u32::<LittleEndian>()?,
            aux_offset: reader.read_u32::<LittleEndian>()?,
            next_offset: reader.read_u32::<LittleEndian>()?,
        })
    }
}

impl VersionSection {
    pub fn new(headers: &SectionHeaders, reader: &mut Reader) -> Result<Option<VersionSection>> {

        if headers.get(SectionHeaderType::GnuVerNeed).is_none() {
            return Ok(None);
        }

        let header = headers.get(SectionHeaderType::GnuVerNeed)
                            .context("Unable to get version section")?;

        let mut offset: u64 = 0;
        let mut data: Vec<(Vec<VersionAux>, VersionNeed)> = vec![];
        let mut aux: Vec<VersionAux> = vec![];

        let mut cnt = 0;

        while cnt < header.sh_info {
            reader
                .seek(SeekFrom::Start(header.sh_offset + offset))
                .unwrap();

            let verneed = VersionNeed::new(reader)?;
            let mut aux_offset: u64 = verneed.aux_offset as u64;
            let mut i = 0;

            while i < verneed.aux_count {
                reader
                    .seek(SeekFrom::Start(header.sh_offset + offset + aux_offset))?;

                let au = VersionAux::new(reader)?;

                aux_offset += au.next as u64;
                aux.push(au);
                i += 1;
            }

            offset += verneed.next_offset as u64;
            data.push((aux, verneed));
            aux = vec![];

            cnt += 1;
        }

        let strtab = headers.dynstr(reader)
                            .context("Unable to load get dynamic string")?;
        let name = headers.strtab.get(header.sh_name as u64);

        Ok(Some(VersionSection { data, strtab, name }))
    }
}
impl VersionAux {
    fn new(reader: &mut Reader) -> Result<VersionAux> {
        Ok(VersionAux {
            hash: reader.read_u32::<LittleEndian>()?,
            flags: VersionAuxFlags::new(reader.read_u16::<LittleEndian>()?),
            other: reader.read_u16::<LittleEndian>()?,
            name: reader.read_u32::<LittleEndian>()?,
            next: reader.read_u32::<LittleEndian>()?,
        })
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
