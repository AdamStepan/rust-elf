pub use byteorder::{LittleEndian, ReadBytesExt};
pub use std::io::prelude::*;
pub use std::io::{Cursor, SeekFrom};

pub type Reader = Cursor<Vec<u8>>;
