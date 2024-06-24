use log::*;

fn main() {
    log::set_logger(&win_dbg_logger::DEBUGGER_LOGGER).expect("failed to set logger");
    log::set_max_level(log::LevelFilter::Debug);

    debug!(
        "Hello from a full exe! My main function is located at 0x{:#x}",
        main as usize
    );
}
