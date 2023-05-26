pub mod message_helper;
use std::collections::HashMap;
use std::convert::TryInto;
use std::io::Read;
use std::iter::FromIterator;
use std::str;

#[derive(Debug)]
struct DMLPacket {
    svc_id: u8,
    msg_type: u8,
    length: u16,
    data: Vec<u8>,
}

// already aligned to 4 bytes, no need for #[repr(C, packed)]
#[derive(Debug)]
pub struct Packet {
    header: u16,    // always 0xF00D on non-encrypted
    size: u16,      // total size of packet
    is_control: u8, // if 0 then packet is a DML packet
    opcode: u8,     // otherwise, it has an opcode (should be 0 on DML)
    /* opcode meanings:
    SESSION_OFFER = 0,
    UDP_HELLO = 1,
    KEEP_ALIVE = 3,
    KEEP_ALIVE_RSP = 4,
    SESSION_ACCEPT = 5
     */
    padding: u16, // should also be 0 if DML
    payload: DMLPacket,
}

impl Packet {
    fn new(raw_packet: &Vec<u8>) -> Packet {
        Packet {
            header: u16::from_le_bytes(raw_packet[0..2].try_into().unwrap()),
            size: u16::from_le_bytes(raw_packet[2..4].try_into().unwrap()),
            is_control: raw_packet[4],
            opcode: raw_packet[5],
            padding: u16::from_le_bytes(raw_packet[6..8].try_into().unwrap()),
            payload: DMLPacket {
                svc_id: raw_packet[8],
                msg_type: raw_packet[9],
                length: u16::from_le_bytes(raw_packet[10..12].try_into().unwrap()),
                data: raw_packet[12..raw_packet.len()].iter().cloned().collect(),
            },
        }
    }
}

#[derive(Debug)]
pub struct SessionOffer {
    // control opcode 0
    pub header: u16,
    pub size: u16,
    pub is_control: u8,
    pub opcode: u8,
    pub padding: u16,
    pub sid: u16,
    pub time_high: u32,
    pub time_low: u32,
    pub time_milli: u32,
    pub length: u32,
    pub data: Vec<u8>,
    pub null_term: u8,
}

impl SessionOffer {
    pub(crate) fn new(raw_packet: &Vec<u8>) -> SessionOffer {
        SessionOffer {
            header: u16::from_le_bytes(raw_packet[0..2].try_into().unwrap()),
            size: u16::from_le_bytes(raw_packet[2..4].try_into().unwrap()),
            is_control: raw_packet[4],
            opcode: raw_packet[5],
            padding: u16::from_le_bytes(raw_packet[6..8].try_into().unwrap()),
            sid: u16::from_le_bytes(raw_packet[8..10].try_into().unwrap()),
            time_high: u32::from_le_bytes(raw_packet[10..14].try_into().unwrap()),
            time_low: u32::from_le_bytes(raw_packet[14..18].try_into().unwrap()),
            time_milli: u32::from_le_bytes(raw_packet[18..22].try_into().unwrap()),
            length: u32::from_le_bytes(raw_packet[22..26].try_into().unwrap()),
            data: raw_packet[26..raw_packet.len() - 1]
                .iter()
                .cloned()
                .collect(),
            null_term: raw_packet[raw_packet.len() - 1],
        }
    }
}

#[derive(Debug)]
pub struct FormattedMessageField {
    pub name: String,
    pub value: String,
    pub vec_val: Vec<u8>,
}

impl FormattedMessageField {
    pub fn new(name: String, value: String) -> FormattedMessageField {
        FormattedMessageField {
            name,
            value,
            vec_val: vec![],
        }
    }

    pub fn new_vec(name: String, vec_val: Vec<u8>) -> FormattedMessageField {
        FormattedMessageField {
            name,
            value: String::from(""),
            vec_val,
        }
    }
}

#[derive(Debug)]
pub struct FormattedPacket {
    name: String,
    pub args: Vec<FormattedMessageField>,
}

impl FormattedPacket {
    fn new(name: String) -> FormattedPacket {
        FormattedPacket { name, args: vec![] }
    }

    fn push(&mut self, val: FormattedMessageField) {
        self.args.push(val);
    }

    pub fn get_arg(&mut self, name: &str) -> Option<String> {
        for arg in &self.args {
            if arg.name == name {
                return Some(String::from(arg.value.to_string()));
            }
        }
        None
    }

    pub fn get_arg_vec(&mut self, name: &str) -> Option<Vec<u8>> {
        for arg in &self.args {
            if arg.name == name {
                return Some(arg.vec_val.clone());
            }
        }
        None
    }
}

/*
\x0d\xf0 <- magic
\x1A\x00 <- data len
\x01 <- is control
\x00 <- opcode (session offer)
\x00\x00\x00\x00 <- reserved
\x22\x00 <- session id
\x00\x00\x00\x00 <- high of timestamp
\x00\x00\x00\x00 <- low of timestamp
\x00\x00\x00\x00 <- some milliseconds
\x01\x00\x00\x00 <- length prefix
\x00\x00 <- null bytes
 */

pub struct Deserializer<'a> {
    services: &'a HashMap<u8, message_helper::Service>,
}

impl Deserializer<'_> {
    pub fn deserialize(&self, raw_packet: Vec<u8>, string_is_vec: bool) -> Option<FormattedPacket> {
        let p = Packet::new(&raw_packet);

        if p.is_control == 1 {
            // TODO: implement control packets?
            return None;
        }

        let svc = match self.services.get(&p.payload.svc_id) {
            Some(s) => s,
            None => {
                println!("Couldn't find service {}", p.payload.svc_id);
                return None;
            }
        };

        let msg = match svc.messages.get((p.payload.msg_type - 1) as usize) {
            Some(m) => m,
            None => {
                println!(
                    "Couldn't find message {} in {}",
                    p.payload.msg_type, svc.name
                );
                return None;
            }
        };

        let mut ret = FormattedPacket::new(msg.name.clone());

        let mut pos = 0;
        for arg in &msg.args {
            match arg.typename.as_str() {
                "UBYT" => {
                    let val: u8 = p.payload.data[pos];
                    ret.push(FormattedMessageField::new(
                        arg.name.to_string(),
                        val.to_string(),
                    ));
                    pos += 1;
                }
                "BYT" => {
                    let val: i8 = p.payload.data[pos] as i8;
                    ret.push(FormattedMessageField::new(
                        arg.name.to_string(),
                        val.to_string(),
                    ));
                    pos += 1;
                }
                "USHRT" => {
                    let val: u16 =
                        u16::from_le_bytes(p.payload.data[pos..pos + 2].try_into().unwrap());
                    ret.push(FormattedMessageField::new(
                        arg.name.to_string(),
                        val.to_string(),
                    ));
                    pos += 2;
                }
                "SHRT" => {
                    let val: i16 =
                        i16::from_le_bytes(p.payload.data[pos..pos + 2].try_into().unwrap());
                    ret.push(FormattedMessageField::new(
                        arg.name.to_string(),
                        val.to_string(),
                    ));
                    pos += 2;
                }
                "UINT" => {
                    let val: u32 =
                        u32::from_le_bytes(p.payload.data[pos..pos + 4].try_into().unwrap());
                    ret.push(FormattedMessageField::new(
                        arg.name.to_string(),
                        val.to_string(),
                    ));
                    pos += 4;
                }
                "INT" => {
                    let val: i32 =
                        i32::from_le_bytes(p.payload.data[pos..pos + 4].try_into().unwrap());
                    ret.push(FormattedMessageField::new(
                        arg.name.to_string(),
                        val.to_string(),
                    ));
                    pos += 4;
                }
                "FLT" => {
                    let val: f32 =
                        f32::from_le_bytes(p.payload.data[pos..pos + 4].try_into().unwrap());
                    ret.push(FormattedMessageField::new(
                        arg.name.to_string(),
                        val.to_string(),
                    ));
                    pos += 4;
                }
                "GID" => {
                    let val: i64 =
                        i64::from_le_bytes(p.payload.data[pos..pos + 8].try_into().unwrap());
                    ret.push(FormattedMessageField::new(
                        arg.name.to_string(),
                        val.to_string(),
                    ));
                    pos += 8;
                }
                "STR" => {
                    let str_sz: u16 =
                        u16::from_le_bytes(p.payload.data[pos..pos + 2].try_into().unwrap());
                    pos += 2;
                    let val: Vec<u8> = Vec::from_iter(
                        p.payload.data[pos..(pos + str_sz as usize)].iter().cloned(),
                    );
                    if string_is_vec {
                        ret.push(FormattedMessageField::new_vec(arg.name.to_string(), val));
                    } else {
                        let str = String::from_utf8_lossy(&val).to_string();
                        ret.push(FormattedMessageField::new(arg.name.to_string(), str));
                    }
                    pos += str_sz as usize;
                }
                _ => {
                    println!("Unimplemented type!");
                    return None;
                }
            }
        }

        return Some(ret);
    }

    pub fn new(services: &HashMap<u8, message_helper::Service>) -> Deserializer {
        Deserializer { services }
    }
}

#[derive(Debug)]
pub enum ArgType {
    Ubyt(u8),
    Byt(i8),
    Ushrt(u16),
    Shrt(i16),
    Uint(u32),
    Int(i32),
    Flt(f32),
    Gid(u64),
    Str(String),
    Vec(Vec<u8>),
}

pub struct Serializer<'a> {
    services: &'a HashMap<u8, message_helper::Service>,
    message_table: HashMap<String, u8>,
}

impl Serializer<'_> {
    pub fn new(services: &HashMap<u8, message_helper::Service>) -> Serializer {
        Serializer {
            services,
            message_table: message_helper::Service::message_table(&services),
        }
    }

    // Not sure how args should be passed yet
    pub fn serialize(&self, name: &str, args: Vec<ArgType>) -> Option<Vec<u8>> {
        // Get the service id for the name (eg MSG_PING) here
        let service_id = match self.message_table.get(name) {
            Some(id) => id,
            None => {
                println!("Could not find this message");
                return None;
            }
        };

        let service = self.services.get(service_id).unwrap();
        let (msg, i) = match service.get_message(name.to_string()) {
            Some(m) => m,
            None => {
                println!("Message not found in service {}!", service.name);
                return None;
            }
        };

        //println!("Found {} at index {} of {} service\n{:#?}", name, i, service.name, msg);

        let mut ret = vec![];

        let mut data: Vec<u8> = vec![]; // packet data (start of args)

        for arg in args {
            match arg {
                ArgType::Ubyt(val) => {
                    data.push(val);
                }
                ArgType::Byt(val) => {
                    data.push(val as u8);
                }
                ArgType::Ushrt(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Shrt(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Uint(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Int(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Flt(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Gid(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Str(val) => {
                    data.extend_from_slice(&(val.len() as u16).to_le_bytes());
                    data.extend_from_slice(val.as_bytes());
                }
                ArgType::Vec(val) => {
                    data.extend_from_slice(&(val.len() as u16).to_le_bytes());
                    data.extend_from_slice(val.as_slice());
                }
                _ => {
                    println!("Unimplemented type!");
                    return None;
                }
            }
        }

        data.push(0);
        ret.extend_from_slice(&(0xf00d as u16).to_le_bytes());
        ret.extend_from_slice(&((8 + data.len()) as u16).to_le_bytes()); // size of header
        ret.push(0); // TODO: add control packets (is_control)
        ret.push(0); // TODO: add control packets (opcode)
        ret.extend_from_slice(&(0 as u16).to_le_bytes());
        ret.push(service_id.clone());
        ret.push((i + 1) as u8);
        ret.extend_from_slice(&((3 + data.len()) as u16).to_le_bytes()); // 3 + to account for size in dml and added bit (idk why but it's in the packet so..)
        ret.extend(data.iter());

        return Some(ret);
    }

    pub fn serialize_control(&self, opcode: u8, args: Vec<ArgType>) -> Option<Vec<u8>> {
        let mut ret = vec![];

        let mut data: Vec<u8> = vec![]; // packet data (start of args)

        for arg in args {
            match arg {
                ArgType::Ubyt(val) => {
                    data.push(val);
                }
                ArgType::Byt(val) => {
                    data.push(val as u8);
                }
                ArgType::Ushrt(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Shrt(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Uint(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Int(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Flt(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Gid(val) => {
                    data.extend_from_slice(&val.to_le_bytes());
                }
                ArgType::Str(val) => {
                    data.extend_from_slice(&(val.len() as u16).to_le_bytes());
                    data.extend_from_slice(val.as_bytes());
                }
                _ => {
                    println!("Unimplemented type!");
                    return None;
                }
            }
        }

        ret.extend_from_slice(&(0xf00d as u16).to_le_bytes());
        ret.extend_from_slice(&((4 + data.len()) as u16).to_le_bytes()); // size of header
        ret.push(1); // is_control
        ret.push(opcode); // control opcode
        ret.extend_from_slice(&(0 as u16).to_le_bytes()); // control reserved
        ret.extend(data.iter());

        return Some(ret);
    }
}
