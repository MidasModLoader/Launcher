use std::{
    fs::{self, File},
    io::Read,
};

mod PatchClient;

use async_process::Command;
use PatchClient::install_min;

mod WizClient;
mod crypto;
mod packet_helper;
mod table_list_parser;

#[macro_use]
extern crate num_derive;

use crate::PatchClient::get_ck2;

#[tokio::main]
async fn main() {
    install_min().await;

    let username = String::from("bighelp25");
    let password = String::from("bighelp25");
    let (ck2, uid) = match get_ck2(username.clone(), password) {
        Ok((ck2, uid)) => (ck2, uid),
        Err(e) => panic!("{}", e),
    };
    println!("{} {}", ck2, uid);

    let mut launch = Command::new("sh");
    launch.current_dir("/home/binarybandit/Desktop/Wizard101Launcher/test/Bin");
    launch.arg("-c");
    launch.arg(format!(
        "wine WizardGraphicalClient.exe -L login.us.wizard101.com 12000 -U ..{} {} {}",
        uid, ck2, username
    ));
    launch.spawn().unwrap();
}
