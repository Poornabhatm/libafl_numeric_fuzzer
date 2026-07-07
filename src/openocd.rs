use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub struct OpenOcd {
    stream: TcpStream,
}

impl OpenOcd {
    const TOKEN: u8 = 0x1a;

    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        println!("Connected to OpenOCD at {}", addr);
        Ok(Self { stream })
    }

    pub fn send_command(&mut self, command: &str) -> std::io::Result<String> {
        let full_command = format!("{}{}", command, Self::TOKEN as char);
        self.stream.write_all(full_command.as_bytes())?;

        let mut response = Vec::new();
        let mut buf = [0u8; 1024];

        loop {
            let n = self.stream.read(&mut buf)?;

            if n == 0 {
                break;
            }

            if let Some(pos) = buf[..n].iter().position(|&b| b == Self::TOKEN) {
                response.extend_from_slice(&buf[..pos]);
                break;
            } else {
                response.extend_from_slice(&buf[..n]);
            }
        }

        Ok(String::from_utf8_lossy(&response).to_string())
    }

    pub fn reset_init(&mut self) -> std::io::Result<()> {
        self.send_command("reset init")?;
        Ok(())
    }

    pub fn load_program(&mut self, binary_path: &str, start_addr: u32) -> std::io::Result<()> {
        println!("Loading program: {}", binary_path);

        self.reset_init()?;
        self.send_command(&format!("load {}", binary_path))?;

        self.halt()?;
        self.set_pc(start_addr)?;
        self.halt()?;

        println!("Program loaded successfully.");
        Ok(())
    }

    pub fn halt(&mut self) -> std::io::Result<()> {
        self.send_command("halt 1000")?;
        Ok(())
    }

    pub fn resume(&mut self) -> std::io::Result<()> {
        self.send_command("resume")?;
        Ok(())
    }

    pub fn set_pc(&mut self, pc: u32) -> std::io::Result<()> {
        self.send_command(&format!("set_reg {{pc 0x{:08x}}}", pc))?;
        Ok(())
    }

    pub fn write_input_to_ram(&mut self, addr: u32, data: &[u8]) -> std::io::Result<()> {
        for (i, byte) in data.iter().enumerate() {
            let target_addr = addr + i as u32;
            self.send_command(&format!("mwb 0x{:08x} 0x{:02x}", target_addr, byte))?;
        }

        Ok(())
    }
}