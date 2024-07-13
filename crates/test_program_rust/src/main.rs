#[cfg(feature = "debug")]
use log::*;

use std::{io::Write, path::PathBuf};

fn main() {
    #[cfg(feature = "debug")]
    {
        log::set_logger(&win_dbg_logger::DEBUGGER_LOGGER).expect("failed to set logger");
        log::set_max_level(log::LevelFilter::Debug);

        debug!(
            "Hello from a full exe! My main function is located at 0x{:#x}",
            main as usize
        );

        debug!("My arguments are:");
        for arg in std::env::args() {
            debug!("{} {:p}", arg, arg.as_ptr());
        }
    }

    #[cfg(not(feature = "debug"))]
    {
        let app_data = std::env::var("LOCALAPPDATA").expect("failed to get %LOCALAPPDATA%");

        let file_path = PathBuf::from(format!("{}\\..\\LocalState\\stage3_complete.txt", app_data));
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(
            &mut file,
            "if you're reading this, stage3 successfully loaded and ran by the PE loader"
        )
        .expect("failed to write to output");

        for arg in std::env::args() {
            writeln!(&mut file, "{:p} {}", arg.as_ptr(), arg).expect("failed to write to outpu");
        }
        drop(file);

        #[cfg(feature = "network")]
        {
            if file_path.exists() {
                let file_data = std::fs::read(&file_path).unwrap();
                // Talk to the remote server
                let mut socket = std::net::TcpStream::connect("192.168.1.74:8081").unwrap();
                let _ = socket.write_all(&file_data);
            }
        }
    }
}
