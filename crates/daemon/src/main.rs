use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    fmt::{self, time::LocalTime},
    layer::SubscriberExt,
    Layer,
};

use tracing_subscriber::{
    field::RecordFields,
    fmt::{
        format::{Pretty, Writer},
        FormatFields,
    },
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};

use std::time::Duration;
use std::{collections::HashMap, env};
use std::{mem::offset_of, net::SocketAddr};
use std::{sync::Arc, thread::current};

use async_trait::async_trait;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use russh_keys::key::KeyPair;
use russh_sftp::protocol::{File, FileAttributes, Handle, Name, Status, StatusCode, Version};
use tokio::sync::Mutex;

mod sftp;

// Janky hack to address https://github.com/tokio-rs/tracing/issues/1817
struct NewType(Pretty);

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
    let file_appender =
        tracing_appender::rolling::daily(env::var("LOCALAPPDATA").unwrap(), "daemon.log");
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

    crate::sftp::start_sftp_server().await;
}
