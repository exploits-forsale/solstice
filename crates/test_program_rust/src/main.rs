#[cfg(feature = "debug")]
use log::*;

fn main() {
    #[cfg(feature = "debug")]
    {
        log::set_logger(&win_dbg_logger::DEBUGGER_LOGGER).expect("failed to set logger");
        log::set_max_level(log::LevelFilter::Debug);

        debug!(
            "Hello from a full exe! My main function is located at 0x{:#x}",
            main as usize
        );
    }

    #[cfg(not(feature = "debug"))]
    {
        let app_data = std::env::var("LOCALAPPDATA").expect("failed to get %LOCALAPPDATA%");
        std::fs::write(
            format!("{}\\..\\LocalState\\stage3_complete.txt", app_data),
            b"if you're reading this, stage3 successfully loaded and ran by the PE loader",
        )
        .expect("failed to write to LocalState");
    }
}
