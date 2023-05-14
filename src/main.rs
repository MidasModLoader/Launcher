mod TableListParser;
mod WizClient;
mod crypto;
mod packet_helper;

//use crate::crypto::rec1::test_generate_rec1;
use crate::packet_helper::{message_helper, ArgType};
use crate::TableListParser::TableList;
use crate::WizClient::Connection;
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::net::Shutdown::Both;
use std::net::TcpListener;
use WizClient::Client;
extern crate flame;
#[macro_use]
extern crate flamer;

#[macro_use]
extern crate num_derive;

#[flame]
fn main() {
    let client = Client::new();

    // Have no idea if the following actually elides a copy
    let services = message_helper::get_services();

    let mut stream = client.create_stream("login.us.wizard101.com:12500");
    let session_offer_raw = &client.recv(&stream);
    let session_offer = packet_helper::SessionOffer::new(&session_offer_raw);
    println!("Got session offer: {:#X?}", session_offer);
    //println!("{:02X?}", login_data.gen_twofish_key());

    //test_generate_rec1();

    let serializer = packet_helper::Serializer::new(&services);
    let file_list = match serializer.serialize(
        "MSG_LATEST_FILE_LIST_V2",
        vec![
            ArgType::Uint(0),
            ArgType::Str(String::from("")),
            ArgType::Uint(0),
            ArgType::Uint(0),
            ArgType::Uint(1),
            ArgType::Uint(0),
            ArgType::Str(String::from("")),
            ArgType::Str(String::from("")),
            ArgType::Str(String::from("")),
            ArgType::Str(String::from("English")),
        ],
    ) {
        Some(v) => v,
        None => {
            println!("Didn't get return from serialize.");
            return;
        }
    };
    client.send(&stream, file_list.as_slice());
    println!("Sent MSG_LATEST_FILE_LIST_V2 packet");
    let buf = client.recv(&stream);
    let deserializer = packet_helper::Deserializer::new(&services);
    let mut deserialized_file_list = deserializer.deserialize(buf).unwrap();
    println!("server returned {:#X?}", deserialized_file_list);

    let latest_file_list_url = match deserialized_file_list.get_arg("ListFileURL") {
        Some(x) => x,
        None => String::from(""),
    };

    println!("Got latest file list: {}", latest_file_list_url);

    let resp = reqwest::blocking::get(latest_file_list_url).expect("request failed");
    let mut content = Cursor::new(resp.bytes().unwrap());
    let mut out = File::create("LatestFileList.bin").expect("failed to create file");
    std::io::copy(&mut content, &mut out).expect("failed to copy content");

    let tab = TableList::from_file("./LatestFileList.bin");
    println!("{:#06X?}", tab);

    // you take URLPrefix and append SRcFileNAme from http://patch.us.wizard101.com/WizPatcher/Windows/LatestFileList.xml (latestfilelist.bin)
    // for example: http://versionec.us.wizard101.com/WizPatcher/V_r735422.Wizard_1_510/LatestBuild/Data/GameData/Avalon-Interiors-AV_Z05_TowerFroudling01.wad

    flame::dump_html(File::create("flamegraph.html").unwrap()).unwrap();
}
