use std::{
    cmp::min,
    error::Error,
    fs::File,
    io::{Bytes, Cursor, Write},
    thread,
    time::Duration,
};

use crate::{
    crypto::rec1::{decrypt_rec1, gen_rec1},
    packet_helper::{self, message_helper, ArgType, FormattedPacket},
    table_list_parser::{self, PatchFile, TableList},
    WizClient::{self, Connection},
};

pub struct Patcher {
    base_url: String,
    file_list: Vec<PatchFile>,
    game_dir: String,
}

use chrono::prelude::*;

use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use tokio::{runtime::Runtime, task};

use std::net::Shutdown::Both;
use std::net::TcpListener;

impl Patcher {
    pub async fn download_file(client: &Client, url: &str, path: &str) -> Result<(), String> {
        let path_p = std::path::Path::new(&path);

        if path_p.exists() {
            return Ok(());
        }

        let prefix = path_p.parent().unwrap();
        std::fs::create_dir_all(prefix).unwrap();

        // Reqwest setup
        let res: reqwest::Response = loop {
            match client
                .get(url)
                .send()
                .await
                .or(Err(format!("Failed to GET from '{}'", &url)))
            {
                Ok(res) => break res,
                Err(e) => {
                    println!("timeout error: {:#?}", e);
                    thread::sleep(Duration::from_millis(2000));
                    continue;
                }
            }
        };

        let total_size = res
            .content_length()
            .ok_or(format!("Failed to get content length from '{}'", &url))?;

        println!(
            "Downloading {}",
            path_p.file_name().unwrap().to_str().unwrap()
        );

        // download chunks
        let mut file = File::create(path).or(Err(format!("Failed to create file '{}'", path)))?;
        let mut downloaded: u64 = 0;
        let mut stream = res.bytes_stream();

        while let Some(item) = stream.next().await {
            let chunk = item.or(Err(format!("Error while downloading file")))?;
            file.write_all(&chunk)
                .or(Err(format!("Error while writing to file")))?;
            let new = min(downloaded + (chunk.len() as u64), total_size);
            downloaded = new;
        }
        return Ok(());
    }

    pub async fn init(game_dir: String, mut file_list: FormattedPacket) -> Patcher {
        let latest_file_list_url = match file_list.get_arg("ListFileURL") {
            Some(x) => x,
            None => String::from(""),
        };

        let base_url = match file_list.get_arg("URLPrefix") {
            Some(x) => x,
            None => String::from(""),
        };
        println!("Got latest file list: {}", latest_file_list_url);

        Self::download_file(
            &Client::new(),
            &latest_file_list_url,
            &String::from("LatestFileList.bin"),
        )
        .await
        .unwrap();

        let file_list = TableList::from_file("./LatestFileList.bin");

        Patcher {
            base_url: base_url,
            file_list: file_list.get_records(),
            game_dir: game_dir,
        }
    }

    pub async fn patch(self, thread_count: usize, only_essential: bool) {
        let thread_chunks: Vec<Vec<PatchFile>> = self
            .file_list
            .chunks(thread_count)
            .map(|chunk| chunk.to_vec())
            .collect();

        let mut tasks = Vec::new();
        for chunk in thread_chunks {
            let base_url = self.base_url.clone();
            let game_dir = self.game_dir.clone();

            tasks.push(task::spawn(async move {
                for file in chunk {
                    let mut write_path = file.src_name.clone();
                    let src_name = file.src_name;
                    if only_essential {
                        if !src_name.contains("Root.wad")
                            && !src_name.contains("Bin")
                            && !src_name.contains("PatchClient")
                            && !src_name.contains("GameData")
                        {
                            continue;
                        }

                        if src_name.contains("GameData")
                            && src_name.contains(".wad")
                            && !src_name.contains("Root.wad")
                            && !src_name.contains("GUI")
                            && !src_name.contains(".xml")
                        {
                            continue;
                        }

                        if src_name.contains("Windows/Bin/") {
                            write_path = src_name.replace("Windows/Bin/", "Bin/");
                        }
                    }
                    Self::download_file(
                        &Client::new(),
                        &format!("{}/{}", &base_url, src_name),
                        &format!("{}{}", &game_dir, write_path),
                    )
                    .await
                    .unwrap();
                }
            }));
        }

        for task in tasks {
            task.await;
        }
    }
}

pub fn get_ck2(username: String, password: String) -> Result<(String, u64), String> {
    let client: WizClient::Client = WizClient::Client::new();
    let services = message_helper::get_services();

    let stream = client.create_stream("165.193.63.4:12000");

    let serializer = packet_helper::Serializer::new(&services);

    let session_offer_raw = &client.recv(&stream);
    let session_offer = packet_helper::SessionOffer::new(&session_offer_raw);
    println!("Got session offer: {:#X?}", session_offer);

    let dt = Utc::now();
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let offer_resp = match serializer.serialize_control(
        0x5,
        vec![
            ArgType::Ushrt(0),                              // reserved
            ArgType::Int(0), // [time high] if you're reading this in 136 years, you will need to implement the upper 4 bytes of the timestamp
            ArgType::Int(since_the_epoch.as_secs() as i32), // time low
            ArgType::Uint(dt.timestamp_subsec_millis()), // time millis in current second
            ArgType::Ushrt(session_offer.sid), // sid
            ArgType::Uint(1), // data len
            ArgType::Ubyt(0), // data always 0 from what i've seen for auth packet
            ArgType::Ubyt(0), // reserved; always zero
        ],
    ) {
        Some(v) => v,
        None => {
            return Err(String::from(
                "Didn't get return from serialize for session offer resp.",
            ));
        }
    };
    println!("Sending offer resp: {:02X?}", offer_resp);
    client.send(&stream, offer_resp.as_slice());

    let rec1 = gen_rec1(
        username,
        password,
        session_offer.sid,
        session_offer.time_low,
        session_offer.time_milli,
    );

    let authen = match serializer.serialize(
        "MSG_USER_AUTHEN_V3",
        vec![
            ArgType::Vec(rec1),                    // rec1
            ArgType::Str(String::from("")),        // version
            ArgType::Str(String::from("")),        // revision
            ArgType::Str(String::from("")),        // datarevision
            ArgType::Str(String::from("")),        // crc
            ArgType::Gid(80202068872285),          // machineid
            ArgType::Str(String::from("English")), // locale
            ArgType::Str(String::from(
                "{C622962F-82EB-40D2-8915-613F91B87F52}:{HW-ID-SMBIOS}",
            )), // patchclientid
            ArgType::Uint(0),                      // issteamclient
        ],
    ) {
        Some(v) => v,
        None => {
            println!("Didn't get return from serialize.");
            return Err(String::from(
                "Didn't get return from serialize for authen v3.",
            ));
        }
    };
    client.send(&stream, authen.as_slice());

    let buf = client.recv(&stream);
    let deserializer = packet_helper::Deserializer::new(&services);
    let mut deserialized_auth_rsp = deserializer.deserialize(buf, true).unwrap();
    println!("server returned packet {:#X?}", deserialized_auth_rsp);

    let mut server_rec1 = match deserialized_auth_rsp.get_arg_vec("Rec1") {
        Some(x) => x,
        None => vec![],
    };

    let reason = match deserialized_auth_rsp.get_arg_vec("Reason") {
        Some(x) => x,
        None => vec![],
    };

    if server_rec1.len() == 0 {
        if reason.len() > 0 {
            return Err(format!(
                "Could not login. Reason: {}",
                String::from_utf8(reason).unwrap().to_string()
            ));
        }
    }

    let mut uid = match deserialized_auth_rsp.get_arg("UserID") {
        Some(x) => x.parse::<u64>().unwrap(),
        None => 0,
    };
    assert_ne!(uid, 0);

    return Ok((
        decrypt_rec1(
            &mut server_rec1,
            session_offer.sid,
            session_offer.time_low,
            session_offer.time_milli,
        ),
        uid,
    ));
}

pub async fn install_min() {
    let client: WizClient::Client = WizClient::Client::new();
    let services = message_helper::get_services();
    let serializer = packet_helper::Serializer::new(&services);

    let stream = client.create_stream("165.193.63.4:12500");

    let session_offer_raw = &client.recv(&stream);
    let session_offer = packet_helper::SessionOffer::new(&session_offer_raw);
    println!("Got session offer: {:#X?}", session_offer);

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

    let buf = client.recv(&stream);
    let deserializer = packet_helper::Deserializer::new(&services);
    let deserialized_file_list = deserializer.deserialize(buf, false).unwrap();
    println!("server returned packet {:#X?}", deserialized_file_list);

    let patcher = Patcher::init(String::from("./test/"), deserialized_file_list).await;
    patcher.patch(50, true).await;
    println!("Finished patching... ready to launch.");
}
