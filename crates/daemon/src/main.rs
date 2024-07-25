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
use windows::{
    core::BSTR,
    Win32::{
        Foundation::{CloseHandle, HANDLE, VARIANT_BOOL},
        NetworkManagement::WindowsFirewall::{
            INetFwRule, NetFwRule, NET_FW_ACTION_ALLOW, NET_FW_IP_PROTOCOL_ANY,
            NET_FW_IP_PROTOCOL_TCP, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_PROFILE_STANDARD,
            NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT,
        },
    },
};

use std::{collections::HashMap, env};
use std::{mem::offset_of, net::SocketAddr};
use std::{path::PathBuf, time::Duration};
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

use anyhow::Context;
use std::io::prelude::*;
use winreg::enums::*;
use winreg::types::FromRegValue;
use winreg::RegKey;

fn dump_key(root_key: &RegKey, path: String) {
    debug!("Dumping {}", path);
    match root_key.open_subkey(&path).context("open subkey") {
        Err(e) => {
            error!("failed to open subkey {}", &path);
            return;
        }
        Ok(key) => {
            for (key, value) in key.enum_values().filter_map(|key| key.ok()) {
                debug!("{key} = {value}");
            }

            for subkey in key.enum_keys().filter_map(|key| key.ok()) {
                dump_key(root_key, format!("{path}\\{subkey}"));
            }
        }
    }
}

fn set_firewall_rules() -> anyhow::Result<()> {
    debug!("setting firewall rules");

    // let value_in = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|Profile=Public|App=System|Name=In|Desc=In|EmbedCtxt=Xbox SystemOS|";

    // let keys = [
    //     "OSDATA\\FwStore\\Local\\FirewallXboxRules",
    //     "OSDATA\\FwStore\\Local\\FirewallRules",
    //     "OSDATA\\FwStore\\AppIso\\FirewallXboxRules",
    //     "OSDATA\\FwStore\\AppIso\\FirewallRules",
    // ];

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // for key in keys {
    //     let (firewall_rules, disp) = hklm.create_subkey(&key).context("opening subkey")?;

    //     for value in firewall_rules.enum_values() {
    //         match value {
    //             Err(e) => error!("key error: {:?}", e),
    //             Ok((name, value)) => {
    //                 // debug!("Key: {}, value: {:?}", &name, &value);
    //                 let value =
    //                     String::from_reg_value(&value).context("converting to reg value")?;
    //                 if value.contains("Action=Block") {
    //                     // debug!("setting rule to Action=Allow");
    //                     firewall_rules
    //                         .set_value(name, &value.replace("Action=Block", "Action=Allow"))
    //                         .context("setting new reg valuef rom Action=block")?;
    //                 }
    //             }
    //         }
    //     }

    //     debug!(
    //         "Old key value AllowAnyProgramPortIn: {:?}",
    //         firewall_rules.get_value::<String, _>("AllowAnyProgramAnyPortIn")
    //     );

    //     debug!("key disposition: {:?}", disp);

    //     firewall_rules
    //         .set_value("AllowAnyProgramAnyPortIn", &value_in)
    //         .context("adding PortIn rule")?;
    // }

    let keys = [
        "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile",
        "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
    ];

    for key in keys {
        let profile = hklm.open_subkey(key).context("opening profile key")?;
        debug!(
            "{} EnableFirewall = {:?}",
            key,
            profile.get_value::<u32, _>("EnableFirewall")
        );

        let (logging, disp) = hklm
            .create_subkey(format!("{key}\\Logging"))
            .context("opening profile logging key")?;

        debug!("logging key created with disp: {:?}", disp);
        logging
            .set_value("LogDroppedPackets", &1u32)
            .context("setting LogDroppedPackets")?;
    }

    dump_key(
        &hklm,
        "SYSTEM\\ControlSet001\\Services\\SharedAccess\\Parameters\\FirewallPolicy".to_string(),
    );

    Ok(())
}

use windows::Win32::System::Com::*;
fn disable_firewall() -> anyhow::Result<()> {
    debug!("disabling firewall");
    unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .context("CoInitializeEx")?;
        let fw_policy: windows::Win32::NetworkManagement::WindowsFirewall::INetFwPolicy2 =
            windows::Win32::System::Com::CoCreateInstance(
                &windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2,
                None,
                windows::Win32::System::Com::CLSCTX_ALL,
            )
            .context("failed to create NetFwPolicy2")?;

        for profile in [
            NET_FW_PROFILE2_DOMAIN,
            NET_FW_PROFILE2_PUBLIC,
            NET_FW_PROFILE2_PRIVATE,
        ] {
            debug!(
                "Profile {:?} is blocking inbound traffic? {:?}",
                profile,
                fw_policy.get_BlockAllInboundTraffic(profile)
            );
            debug!(
                "Profile {:?} is enabled {:?}",
                profile,
                fw_policy.get_FirewallEnabled(profile)
            );
            debug!(
                "Profile {:?} default inbound action {:?}",
                profile,
                fw_policy.get_DefaultInboundAction(profile)
            );
            debug!(
                "Profile {:?} notifications disabled {:?}",
                profile,
                fw_policy.get_NotificationsDisabled(profile)
            );

            fw_policy
                .put_BlockAllInboundTraffic::<VARIANT_BOOL>(profile, false.into())
                .with_context(|| {
                    format!("failed to reset inbound traffic block for {profile:?}")
                })?;

            fw_policy
                .put_FirewallEnabled::<VARIANT_BOOL>(profile, false.into())
                .with_context(|| format!("failed to disable firewall for {profile:?}"))?;

            fw_policy
                .put_DefaultInboundAction(profile, NET_FW_ACTION_ALLOW)
                .with_context(|| format!("failed to set default inbound action for {profile:?}"))?;

            fw_policy
                .put_NotificationsDisabled::<VARIANT_BOOL>(profile, true.into())
                .context("Disable notifications")?;

            let rules = fw_policy.Rules().context("fw_policy rules")?;

            for (direction_name, direction) in
                [("In", NET_FW_RULE_DIR_IN), ("Out", NET_FW_RULE_DIR_OUT)]
            {
                debug!("Adding rule in {direction_name:?} direction");

                let rule: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_ALL)
                    .context("creating NetFwRule instance")?;

                rule.SetEnabled::<VARIANT_BOOL>(true.into())
                    .context("SetEnabled")?;

                rule.SetName(&BSTR::from(format!(
                    "AllowAnyProgramAnyPortCOM{direction_name}"
                )))
                .context("SetName")?;
                rule.SetApplicationName(&BSTR::from("C:\\Windows\\system32\\conhost.exe"))
                    .context("SetApplicationName")?;
                rule.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0)
                    .context("SetProtocol")?;
                rule.SetAction(NET_FW_ACTION_ALLOW).context("SetAction")?;
                rule.SetDirection(direction).context("SetDirection")?;
                rule.SetDescription(&BSTR::from("Testing"))
                    .context("SetDescription")?;
                rule.SetGrouping(&BSTR::from("Xbox SystemOS"))
                    .context("SetGrouping")?;
                rule.SetProfiles(NET_FW_PROFILE2_ALL.0)
                    .context("SetProfiles")?;
                // rule.SetRemoteAddresses(&BSTR::from("LocalSubnet"))
                //     .context("SetRemoteAddresses")?;
                // rule.SetLocalAddresses(&BSTR::from("LocalSubnet"))
                //     .context("SetRemoteAddresses")?;
                // rule.SetInterfaceTypes(&BSTR::from("All"))
                //     .context("SetInterfaceTypes")?;

                rules.Add(&rule).context("Add rule")?;
            }
        }
    }

    debug!("successfully disabled firewall");

    Ok(())
}

use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error};

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

    use network_interface::*;
    let network_interfaces = network_interface::NetworkInterface::show().unwrap();

    for itf in network_interfaces.iter() {
        debug!("Network interface: {:?}", itf);
    }

    debug!("daemon started");

    // Talk to the remote server
    if let Err(e) = set_firewall_rules() {
        error!("failed to set firewall rules: {:?}", e);
        return;
    }

    if let Err(e) = disable_firewall() {
        error!("failed to disable firewall: {:?}", e);
        return;
    }

    debug!("starting sftp server");

    if let Err(e) = crate::sftp::start_sftp_server().await {
        error!("{}", e);
    }
}
