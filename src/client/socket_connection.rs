use std::{net::{TcpStream, SocketAddr}, io::{self, Write}};

const PORT: u16 = 5287;
const HOST_IP: [u8; 4] = [127, 0, 0, 1];

fn socket_connect() -> io::Result<TcpStream> {
    let tcp_host = SocketAddr::from((HOST_IP, PORT));
    // println!("Connecting to {}", tcp_host);

    TcpStream::connect(tcp_host)
}

pub fn send_buffer(buffer: &[u8]) -> io::Result<()> {
    let mut tcp_connection = socket_connect()?;
    let block_size = 4096;
    let mut index = 0;

    let buffer_size = buffer.len();
    let blocks = (buffer_size - (buffer_size % block_size)) / block_size;

    // println!("buffer size: {}, blocks: {}", buffer_size, blocks);

    loop {
        let mt = (index + 1) * block_size;
        let max_to = if mt >= buffer_size { buffer_size } else { mt };

        // println!("currnet block: {}, from {} to {}", index, index * block_size, max_to);

        tcp_connection.write(&buffer[(index * block_size)..max_to]).expect("Cannot send buffer");

        index += 1;
        
        if index > blocks {
            break;
        }
    }

    tcp_connection.write(&[0u8; 0])?;
    tcp_connection.shutdown(std::net::Shutdown::Both)?;
    
    Ok(())
}