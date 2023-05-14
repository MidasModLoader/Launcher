/*use ofb::cipher::{NewCipher, StreamCipher};
use ofb::Ofb;
use twofish::Twofish;

type TwofishOfb = Ofb<Twofish>;

fn derive_key(sid: u32, time_secs: u32, time_millis: u16) -> [u8; 32] {
    let mut key = [0; 32];

    let sid_bytes = sid.to_le_bytes();
    let time_secs_bytes = time_secs.to_le_bytes();
    let time_millis_bytes = time_millis.to_le_bytes();

    for (i, e) in key.iter_mut().enumerate() {
        *e = 0x17 + i as u8;
    }

    key[4] = sid_bytes[0];
    key[5] = sid_bytes[2];
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
    sid: u32,
    username: &str,
    client_key: &str,
    time_secs: u32,
    time_millis: u16,
) -> Vec<u8> {
    let mut record = format!("{} {} {}", sid, username, client_key).into_bytes();

    let key = &derive_key(sid, time_secs, time_millis);
    let nonce = &derive_nonce();

    let mut twofish = TwofishOfb::new(key.into(), nonce.into());
    twofish.apply_keystream(&mut record);

    record
}

pub fn test_generate_rec1() {
    let client_key = "8XF+NxRb8f9necMm+MHieLn0RrH91C06NaiMRBtHxE+SNrjqIi1l0PoiPSvU/nxSkH9kd2rwjhOoOl4M/ZOhVA==";
    let rec1 = encrypt_rec1(3400, "doglover123", client_key, 1614666209, 757);

    assert_eq!(
        &rec1,
        &[
        150,
        164,
        91,
        83,
        75,
        196,
        160,
        191,
        47,
        109,
        57,
        125,
        208,
        6,
        30,
        101,
        245,
        22,
        181,
        197,
        109,
        131,
        55,
        57,
        250,
        121,
        178,
        225,
        124,
        187,
        17,
        192,
        51,
        41,
        115,
        188,
        132,
        232,
        168,
        59,
        49,
        241,
        189,
        9,
        163,
        133,
        11,
        86,
        82,
        85,
        122,
        12,
        58,
        54,
        65,
        63,
        104,
        159,
        116,
        255,
        184,
        231,
        173,
        91,
        98,
        178,
        207,
        157,
        232,
        45,
        86,
        223,
        232,
        233,
        235,
        120,
        115,
        251,
        241,
        137,
        130,
        8,
        16,
        46,
        66,
        23,
        175,
        203,
        66,
        155,
        219,
        208,
        187,
        132,
        165,
        131,
        143,
        75,
        130,
        124,
        130,
        85,
        177,
        181,
        108,
        ]
    );

    println!("rec1: {:#?}", rec1);
}*/
