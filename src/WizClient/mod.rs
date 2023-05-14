use std::io::prelude::*;
use std::io::{self, Read};
use std::net::TcpStream;

pub struct Client {
    is_connected: bool,
}

pub trait Connection {
    fn is_connected(&self) -> bool;
    fn recv(&self, stream: &TcpStream) -> Vec<u8>;
    fn send(&self, stream: &TcpStream, buf: &[u8]);

    fn create_stream(&self, server_addr: &str) -> TcpStream {
        let stream = TcpStream::connect(server_addr);
        match stream {
            Ok(ref _stream) => println!("Connected to Wizard101 server successfully!"),
            Err(x) => panic!("Failed to connect {}", x),
        };
        let ret = stream.unwrap();
        return ret;
    }
}

impl Client {
    pub fn new() -> Self {
        Client {
            is_connected: false,
        }
    }
}

impl Connection for Client {
    #[allow(dead_code)]
    fn is_connected(&self) -> bool {
        return self.is_connected;
    }

    // https://doc.rust-lang.org/std/net/struct.TcpStream.html#examples-16
    fn recv(&self, mut stream: &TcpStream) -> Vec<u8> {
        let mut x = [0; 0x4]; // 0xf00d, packet total size
        stream.peek(&mut x);
        let mut sz = [0; 2]; // total packet size
        sz.clone_from_slice(&x[2..4]);
        let size = u16::from_le_bytes(sz) + 4; // u16 packet size

        let mut buf = vec![];
        buf.resize(size as usize, 0);

        stream.read(&mut buf);

        return buf;
    }

    fn send(&self, mut stream: &TcpStream, buf: &[u8]) {
        stream.write(buf);
    }
}
