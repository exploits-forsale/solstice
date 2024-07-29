use anyhow::Context;
use firewall::allow_port_through_firewall;
use firewall::disable_firewalls;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::fmt::time::LocalTime;
use tracing_subscriber::fmt::{self};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::format::Pretty;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::FormatFields;

use std::env;
use std::fs::create_dir_all;
use std::path;

use tracing::debug;
use tracing::error;

mod firewall;
mod ssh;
mod sftp;

// Janky hack to address https://github.com/tokio-rs/tracing/issues/1817
struct NewType(Pretty);

pub(crate) const SSH_LISTEN_PORT: u16 = 22;

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
    let appdata_env = env::var("LOCALAPPDATA").unwrap();
    let appdata_dir = path::Path::new(&appdata_env);
    let file_appender =
        tracing_appender::rolling::daily(appdata_dir, "daemon.log");

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    let subscriber = tracing_subscriber::registry()
        .with(
            fmt::Layer::new()
                .pretty()
                // .with_writer(std::io::stdout)
                // .with_timer(LocalTime::rfc_3339())
                .fmt_fields(NewType(Pretty::default()))
                .with_ansi(true)
                .with_filter(LevelFilter::DEBUG),
        )
        .with(
            fmt::Layer::new()
                .with_writer(non_blocking)
                .with_timer(LocalTime::rfc_3339())
                .with_ansi(false)
                .with_filter(LevelFilter::DEBUG),
        );
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    debug!("daemon started");

    #[cfg(feature = "firewall")]
    {
        if let Err(e) = disable_firewalls() {
            error!("failed to disable firewall: {:?}", e);
            return;
        }

        if let Err(e) =
            allow_port_through_firewall("Solstice Daemon - SSH", SSH_LISTEN_PORT).context("SSH")
        {
            error!("failed to allow port through firewall: {:?}", e);
        }
    }

    debug!("starting ssh server");
    let config_dir = &appdata_dir.join("solstice_ssh");
    if !config_dir.exists() {
        if let Err(e) = create_dir_all(config_dir).unwrap() {
            error!("failed to create config dir: {:?}", e);
            return;
        }
    }
    debug!("using config dir: {config_dir:?}");

    if let Err(e) = crate::ssh::start_ssh_server(SSH_LISTEN_PORT, config_dir).await {
        error!("{}", e);
    }
}
