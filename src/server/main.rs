use std::{
    io::{Result, Read, Write},
    net::{SocketAddr, TcpStream, TcpListener},
    fs,
    thread
};

use uuid::Uuid;

const PORT: u16 = 5287;
const HOST_IP: [u8; 4] = [0, 0, 0, 0];

fn handle_come_in_message(mut stream: TcpStream) -> Result<()> {
    let id = Uuid::new_v4();
    let mut file = fs::File::create(format!("{}-{}.json", stream.peer_addr().unwrap().to_string().replace(":", "-"), id.as_simple()))?;

    loop {
        let mut buffer = [0u8; 4096];
        let bytes_read = stream.read(&mut buffer)?;

        if bytes_read == 0 {
            break;
        }

        file.write(&buffer[..bytes_read])?;
    }

    Ok(())
}

fn main() {
    println!("Server Started!");

    let receiver_listener = TcpListener::bind(SocketAddr::from((HOST_IP, PORT))).expect("Cannot bind port");
    let mut threads: Vec<thread::JoinHandle<()>> = Vec::new();

    for stream in receiver_listener.incoming() {
        let stream = stream.expect("Cannot handle incoming message");

        let handle = thread::spawn(move || {
            println!("New client connected! Connected from: {}", stream.peer_addr().unwrap().to_string());
            handle_come_in_message(stream).unwrap_or_else(|error| eprintln!("{:?}", error));
        });
        threads.push(handle);
    }

    for handle in threads {
        handle.join().unwrap();
    }
}
