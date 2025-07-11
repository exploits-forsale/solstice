#![feature(anonymous_pipe)]

use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::time::LocalTime;
use tracing_subscriber::fmt::{self};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::Pretty;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::FormatFields;

use clap::Parser;

use std::env;
use std::fs::create_dir_all;
use std::path;

use tracing::info;
use tracing::error;

mod directory;
mod firewall;
mod sftp;
mod ssh;
mod impersonate;

// Janky hack to address https://github.com/tokio-rs/tracing/issues/1817
struct NewType(Pretty);

pub(crate) const DEFAULT_SSH_LISTEN_PORT: u16 = 22;

#[derive(Parser)]
#[command(name = "solstice-daemon")]
#[command(about = "A windows ssh daemon")]
#[command(version)]
pub struct CliArgs {
    /// Log level verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbosity: u8,

    /// TCP listen port
    #[arg(short = 'p', long = "port", default_value_t = DEFAULT_SSH_LISTEN_PORT)]
    pub listen_port: u16,

    /// Path to configuration root (default: %LOCALAPPDATA%)
    #[arg(short = 'c', long)]
    pub config_root: Option<path::PathBuf>,
}

impl CliArgs {
    pub fn get_log_level(&self) -> LevelFilter {
        match self.verbosity {
            0 => LevelFilter::INFO,
            1 => LevelFilter::DEBUG,
            2.. => LevelFilter::TRACE,
        }
    }
}

impl<'writer> FormatFields<'writer> for NewType {
    fn format_fields<R: RecordFields>(
        &self,
        writer: Writer<'writer>,
        fields: R,
    ) -> core::fmt::Result {
        self.0.format_fields(writer, fields)
    }
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();

    let log_level = args.get_log_level();
    let appdata_env = env::var("LOCALAPPDATA").unwrap();

    let config_root_dir = args.config_root.unwrap_or(path::Path::new(&appdata_env).to_path_buf());
    let file_appender = tracing_appender::rolling::daily(&config_root_dir, "daemon.log");

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let subscriber = tracing_subscriber::registry()
        .with(
            // stdout logger
            fmt::Layer::new()
                .pretty()
                // .with_writer(std::io::stdout)
                // .with_timer(LocalTime::rfc_3339())
                .fmt_fields(NewType(Pretty::default()))
                .with_ansi(true)
                .with_filter(log_level),
        )
        .with(
            // file logger
            fmt::Layer::new()
                .with_writer(non_blocking)
                .with_timer(LocalTime::rfc_3339())
                .with_ansi(false)
                .with_filter(log_level),
        );
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    #[cfg(feature = "firewall")]
    {
        info!("disabling firewall...");

        if let Err(e) = crate::firewall::disable_firewalls() {
            error!("failed to disable firewall: {:?}", e);
            return;
        }

        if let Err(e) =
            crate::firewall::allow_port_through_firewall("Solstice Daemon - SSH", args.listen_port)
        {
            error!("failed to allow port through firewall for SSH: {:?}", e);
        }
    }

    info!("starting ssh server");
    let config_dir = &config_root_dir.join("solstice_ssh");
    if !config_dir.exists() {
        if let Err(e) = create_dir_all(config_dir) {
            error!("failed to create config dir: {:?}", e);
            return;
        }
    }
    info!("using config dir: {config_dir:?}");

    if let Err(e) = crate::ssh::start_ssh_server(args.listen_port, config_dir).await
    {
        error!("failed to start ssh server {:?}", e);
    }
}
