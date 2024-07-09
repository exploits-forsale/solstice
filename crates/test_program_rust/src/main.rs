#[cfg(feature = "debug")]
use log::*;

use std::io::Write;

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
        let mut file =
            std::fs::File::create(format!("{}\\..\\LocalState\\stage3_complete.txt", app_data))
                .unwrap();
        writeln!(
            &mut file,
            "if you're reading this, stage3 successfully loaded and ran by the PE loader"
        )
        .expect("failed to write to output");

        for arg in std::env::args() {
            writeln!(&mut file, "{:p} {}", arg.as_ptr(), arg).expect("failed to write to outpu");
        }
    }
}
