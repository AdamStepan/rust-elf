use crate::program::{ProgramHeaders, SegmentType};
use crate::reader::{Reader, Seek, SeekFrom};
use std::fmt;
use std::io::Read;

#[derive(Debug)]
pub struct Interpret {
    path: String,
}

impl Interpret {
    pub fn new(headers: &ProgramHeaders, reader: &mut Reader) -> Interpret {
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

impl fmt::Display for Interpret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Interpret path: `{}'", self.path)
    }
}
