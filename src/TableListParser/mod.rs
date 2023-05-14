use std::{fs, io::Cursor, rc::Rc};

use eio::ReadExt;

#[repr(u8)]
#[derive(Debug)]
enum ValueTypeT {
    GID = 0x0,
    INT = 0x1,
    FLT = 0x2,
    UINT = 0x3,
    BYT = 0x4,
    UBYT = 0x5,
    USHRT = 0x6,
    DBL = 0x7,
    WSTR = 0x8,
    STR = 0x9,
    NONE = 0x10,
}

fn u8_to_valuetype(val: u8) -> ValueTypeT {
    match val {
        0x0 => ValueTypeT::GID,
        0x1 => ValueTypeT::INT,
        0x3 => ValueTypeT::UINT,
        0x2 => ValueTypeT::FLT,
        0x4 => ValueTypeT::BYT,
        0x5 => ValueTypeT::UBYT,
        0x6 => ValueTypeT::USHRT,
        0x7 => ValueTypeT::DBL,
        0x9 => ValueTypeT::STR,
        0x8 => ValueTypeT::WSTR,
        _ => ValueTypeT::NONE,
    }
}

#[repr(u8)]
#[derive(Debug, FromPrimitive, PartialEq, Copy, Clone)]
enum RecordTypeT {
    MSG_CUSTOMDICT = 0x1,
    MSG_CUSTOMRECORD = 0x2,
    NONE = 0x3,
}

fn u8_to_recordtype(val: u8) -> RecordTypeT {
    match val {
        0x1 => RecordTypeT::MSG_CUSTOMDICT,
        0x2 => RecordTypeT::MSG_CUSTOMRECORD,
        _ => RecordTypeT::NONE,
    }
}

#[derive(Debug)]
pub struct RecordField {
    length: u16,
    name: String, // if _TargetTable then we need to handle differently
    value_type: ValueTypeT,
    dml_flags: u8,
    is_target_table: bool,
}

impl RecordField {
    pub(crate) fn from_cursor(mut cursor: Cursor<Vec<u8>>, is_target_table: bool) -> RecordField {
        let str_len: u16 = cursor.read_le().unwrap();
        let old_pos = cursor.position();
        let mut str_vec: Vec<u8> = Vec::new();
        for _i in 0..str_len {
            str_vec.push(cursor.read_le().unwrap());
        }
        let s = String::from_utf8(str_vec).expect("Invalid name field");
        cursor.set_position(old_pos + str_len as u64);

        if is_target_table {
            return RecordField {
                length: str_len,
                name: s,
                value_type: ValueTypeT::NONE,
                dml_flags: 0,
                is_target_table: is_target_table,
            };
        }
        RecordField {
            length: str_len,
            name: s,
            value_type: u8_to_valuetype(cursor.read_le::<u8>().unwrap()),
            dml_flags: cursor.read_le().unwrap(),
            is_target_table: is_target_table,
        }
    }
}

#[derive(Debug)]
pub struct RecordTemplate {
    record_fields: Vec<RecordField>,
}

impl RecordTemplate {
    pub(crate) fn from_cursor(
        mut cursor: Cursor<Vec<u8>>,
        total_bytes: u16,
        is_target_table: bool,
    ) -> RecordTemplate {
        let mut record_fields = Vec::new();
        let mut consumed = 0;
        let off = if is_target_table { 2 } else { 4 };
        while consumed < total_bytes {
            let record = RecordField::from_cursor(cursor.clone(), is_target_table);
            cursor.set_position(cursor.position() + record.length as u64 + off);
            consumed += record.length + 4;
            record_fields.push(record);
        }
        RecordTemplate {
            record_fields: record_fields,
        }
    }
}

#[derive(Debug)]
pub struct Value {
    protocol_id: u8, // always 2
    record_type: RecordTypeT,
    size: u16,
    records: RecordTemplate,
}

impl Value {
    pub(crate) fn from_cursor(mut cursor: Cursor<Vec<u8>>) -> Value {
        let protocol_id = cursor.read_le().unwrap();
        let record_type = u8_to_recordtype(cursor.read_le::<u8>().unwrap());
        let size = cursor.read_le().unwrap();

        Value {
            protocol_id: protocol_id,
            record_type: record_type,
            size: size,
            records: RecordTemplate::from_cursor(
                cursor.clone(),
                size - 2,
                record_type == RecordTypeT::MSG_CUSTOMRECORD,
            ), // -2 accounting for size field
        }
    }
}

#[derive(Debug)]
pub struct PatchFile {
    src_name: String,
    tar_name: String,
    file_type: u32,
    size: u32,
    header_size: u32,
    compressed_size: u32,
    crc: u32,
    header_crc: u32,
}

impl PatchFile {
    pub(crate) fn from_cursor(mut cursor: Cursor<Vec<u8>>) -> PatchFile {
        let src_name_len: u16 = cursor.read_le().unwrap();
        let mut old_pos = cursor.position();
        let mut src_name_vec: Vec<u8> = Vec::new();
        for _i in 0..src_name_len {
            src_name_vec.push(cursor.read_le().unwrap());
        }

        let src_name = String::from_utf8(src_name_vec).expect("Invalid name field");
        cursor.set_position(old_pos + src_name_len as u64);

        let tar_name_len: u16 = cursor.read_le().unwrap();
        old_pos = cursor.position();
        let mut tar_name_vec: Vec<u8> = Vec::new();
        for _i in 0..tar_name_len {
            tar_name_vec.push(cursor.read_le().unwrap());
        }
        let tar_name = String::from_utf8(tar_name_vec).expect("Invalid name field");
        cursor.set_position(old_pos + tar_name_len as u64);

        PatchFile {
            src_name: src_name,
            tar_name: tar_name,
            file_type: cursor.read_le().unwrap(),
            size: cursor.read_le().unwrap(),
            header_size: cursor.read_le().unwrap(),
            compressed_size: cursor.read_le().unwrap(),
            crc: cursor.read_le().unwrap(),
            header_crc: cursor.read_le().unwrap(),
        }
    }
}

#[derive(Debug)]
pub struct TableList {
    length: u32,
    records: Vec<PatchFile>,
}

impl TableList {
    pub(crate) fn from_file(file_name: &str) -> TableList {
        let mut contents = Cursor::new(fs::read(file_name).expect("Couldn't read tablelist file"));
        let mut records = Vec::new();
        let length = contents.read_le().unwrap(); // need to read here so our cursor is in right pos

        for _i in 0..length + 1 {
            let val = Value::from_cursor(contents.clone());
            contents.set_position(contents.position() + val.size as u64);
            //records.push(val);
        }

        let version = contents.read_le::<i32>().unwrap();

        {
            let val = Value::from_cursor(contents.clone());
            contents.set_position(contents.position() + val.size as u64);
            //records.push(val);
        }

        let unk: [u8; 12] = contents.read_array().unwrap(); // this should be a dict.. but doesn't look right lol 02 02 08 00 01 00 00 00 01 00 00 00

        let mut toggle: bool = false;
        while contents.get_ref().len() > contents.position() as usize {
            if !toggle {
                let val = Value::from_cursor(contents.clone());
                contents.set_position(contents.position() + val.size as u64);
            }

            let protocol_id: u8 = contents.read_le().unwrap(); // skip
            let record_type = u8_to_recordtype(contents.read_le::<u8>().unwrap());

            if record_type == RecordTypeT::MSG_CUSTOMDICT && toggle {
                contents.set_position(contents.position() - 2); // unskip
                let val = Value::from_cursor(contents.clone());
                contents.set_position(contents.position() + val.size as u64);
                contents.set_position(contents.position() + 6);
            }

            if !toggle {
                contents.set_position(contents.position() + 2);
            } else {
                contents.set_position(contents.position() - 2);
            }

            let file = PatchFile::from_cursor(contents.clone());
            if file.src_name.contains("Bin/") && !toggle {
                toggle = true;
            }

            contents.set_position(
                contents.position() + file.src_name.len() as u64 + file.tar_name.len() as u64 + 32, // 32 bc there's a u32 1 at the end? and 2 u16 for string lens
            );
            records.push(file);
        }

        TableList {
            length: length,
            records: records,
        }
    }
}
