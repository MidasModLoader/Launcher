use libdeflater::Decompressor;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::iter::FromIterator;
use std::str;

extern crate flame;

#[repr(C, packed)]
struct Header {
    file_header: [u8; 5],
    version: u32,
    num_files: u32,
    padding: u8,
}

impl Header {
    fn read(buf: &Vec<u8>, pos: usize) -> Self {
        Header {
            file_header: buf[pos..pos + 5].try_into().unwrap(),
            version: u32::from_le_bytes(buf[pos + 5..pos + 9].try_into().unwrap()),
            num_files: u32::from_le_bytes(buf[pos + 9..pos + 13].try_into().unwrap()),
            padding: buf[pos + 13],
        }
    }
}

#[repr(C, packed)]
struct File {
    offset: u32,
    size: u32,
    zip_size: u32,
    zip: u8,
    crc: u32,
    name_size: u32,
}

impl File {
    fn read(buf: &Vec<u8>, pos: usize) -> Self {
        File {
            offset: u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap()),
            size: u32::from_le_bytes(buf[pos + 4..pos + 8].try_into().unwrap()),
            zip_size: u32::from_le_bytes(buf[pos + 8..pos + 12].try_into().unwrap()),
            zip: buf[pos + 12],
            crc: u32::from_le_bytes(buf[pos + 13..pos + 17].try_into().unwrap()),
            name_size: u32::from_le_bytes(buf[pos + 17..pos + 21].try_into().unwrap()),
        }
    }
}

pub struct FileList {
    files: HashMap<String, Vec<u8>>,
}

impl FileList {
    /*let match_str = "GameMessages.xml";
    match file_list.find_file(match_str) {
        Some(x) => println!("Found! {}", str::from_utf8(&x).unwrap().to_string()),
        None => println!("{} doesn't exist in root.wad", match_str)
    }*/
    #[flame]
    pub fn find_file(&self, name: &str) -> Option<&Vec<u8>> {
        return self.files.get(name);
    }

    #[flame]
    pub fn get_files_with_ext(&mut self, pat: &str) -> Vec<(String, Vec<u8>)> {
        let mut ret: Vec<(String, Vec<u8>)> = Vec::new();
        for (key, value) in &self.files {
            ret.push((key.try_into().unwrap(), value.to_vec()));
        }
        ret
    }

    #[flame]
    pub fn get_file_list(file_name: &str) -> FileList {
        let mut files = HashMap::new();
        let contents = fs::read(file_name).expect("Couldn't read wad file");
        let mut current_pos = 0; // drain is SUPER expensive and makes execution take 1000x as long

        let header = Header::read(&contents, current_pos);
        current_pos += std::mem::size_of::<Header>();

        for _i in 0..header.num_files {
            let file = File::read(&contents, current_pos);
            current_pos += std::mem::size_of::<File>();

            let file_name = str::from_utf8(&Vec::from_iter(
                contents[current_pos..(current_pos + (file.name_size - 1) as usize)]
                    .iter()
                    .cloned(),
            ))
            .unwrap()
            .to_string();
            current_pos += (file.name_size) as usize;

            if file_name.find("Messages.xml") == None {
                continue;
            }

            let pos_backup = current_pos;
            current_pos = file.offset as usize;

            if file.zip == 0 {
                let file_data = Vec::from_iter(
                    contents[current_pos..(current_pos + (file.size) as usize)]
                        .iter()
                        .cloned(),
                );
                files.insert(file_name, file_data);
            } else {
                let compressed = Vec::from_iter(
                    contents[current_pos..(current_pos + (file.zip_size) as usize)]
                        .iter()
                        .cloned(),
                );
                let decompressed = {
                    let mut decompressor = Decompressor::new();
                    let mut outbuf = Vec::new();
                    outbuf.resize(file.size as usize, 0);
                    decompressor
                        .zlib_decompress(&compressed, &mut outbuf)
                        .unwrap();
                    outbuf
                };
                files.insert(file_name, decompressed);
            }
            current_pos = pos_backup;
        }

        FileList { files }
    }
}
