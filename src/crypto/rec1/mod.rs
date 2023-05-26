use base64::{engine::general_purpose, Engine as _};
use ofb::cipher::KeyIvInit;
use ofb::cipher::StreamCipher;
use ofb::Ofb;
use twofish::Twofish;

type TwofishOfb = Ofb<Twofish>;

use sha2::{Digest, Sha512};

fn derive_key(sid: u16, time_secs: u32, time_millis: u32) -> [u8; 32] {
    let mut key = [0; 32];

    let sid_bytes = sid.to_le_bytes();
    let time_secs_bytes = time_secs.to_le_bytes();
    let time_millis_bytes = time_millis.to_le_bytes();

    for (i, e) in key.iter_mut().enumerate() {
        *e = 0x17 + i as u8;
    }

    key[4] = sid_bytes[0];
    key[5] = 0;
    key[6] = sid_bytes[1];
    key[8] = time_secs_bytes[0];
    key[9] = time_secs_bytes[2];
    key[12] = time_secs_bytes[1];
    key[13] = time_secs_bytes[3];
    key[14] = time_millis_bytes[0];
    key[15] = time_millis_bytes[1];

    key
}

fn derive_nonce() -> [u8; 16] {
    let mut iv = [0; 16];
    for (i, e) in iv.iter_mut().enumerate() {
        *e = 0xB6 - i as u8;
    }
    iv
}

pub fn encrypt_rec1(
    sid: u16,
    username: &str,
    client_key: &str,
    time_secs: u32,
    time_millis: u32,
) -> Vec<u8> {
    let mut record = format!("{} {} {}", sid, username, client_key).into_bytes();

    let key = &derive_key(sid, time_secs, time_millis);
    let nonce = &derive_nonce();

    let mut twofish = TwofishOfb::new(key.into(), nonce.into());
    twofish.apply_keystream(&mut record);

    record
}

fn gen_ck1(password: &str, sid: u16, time_secs: u32, time_millis: u32) -> String {
    let mut hasher = Sha512::new();
    hasher.update(password);
    let password_hash = general_purpose::STANDARD.encode(hasher.finalize());

    let mut hash2 = Sha512::new();
    hash2.update(password_hash);
    hash2.update(format!("{}{}{}", sid, time_secs, time_millis));

    general_purpose::STANDARD.encode(hash2.finalize())
}

pub fn gen_rec1(
    username: String,
    password: String,
    sid: u16,
    time_secs: u32,
    time_millis: u32,
) -> Vec<u8> {
    let client_key = gen_ck1(&password, sid, time_secs, time_millis);
    encrypt_rec1(sid, &username, &client_key, time_secs, time_millis)
}

pub fn decrypt_rec1(rec1: &mut [u8], sid: u16, time_secs: u32, time_millis: u32) -> String {
    let key = &derive_key(sid, time_secs, time_millis);
    let nonce = &derive_nonce();

    let mut twofish = TwofishOfb::new(key.into(), nonce.into());
    twofish.apply_keystream(rec1);
    String::from_utf8(rec1.to_vec()).unwrap().to_string()
}
