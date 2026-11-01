use crate::config::AppConfig;
use crate::ebpf_loader::{LoadedEbpf, attach_uprobe, create_ring_buffer_async_fd};
use crate::error::{PanhandleError, Result};
use crate::output::OutputConfig;
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::Interest;

/// Handle bash readline monitoring
pub async fn setup_bash_monitoring(
    ebpf: &mut LoadedEbpf,
    config: &AppConfig,
    output: &OutputConfig,
) -> Result<()> {
    let binary_path = find_binary("/bin/bash")?;
    attach_uprobe(
        &mut ebpf.ebpf,
        "readline",
        "readline_internal_teardown",
        &binary_path,
    )?;

    let async_fd = create_ring_buffer_async_fd(&mut ebpf.ebpf, "readline_events")?;

    let executables = config.executables.clone();
    let client = output.client.clone();
    let hostname = output.hostname.clone();
    let json = config.json;
    let http = config.http;
    let syslog = config.syslog;
    let syslog_address = output.syslog_address.clone();
    let http_url = output.http_url.clone();
    let debug = config.debug;

    tokio::spawn(async move {
        consume_shell_events(
            client,
            async_fd,
            executables,
            hostname,
            json,
            http,
            syslog,
            syslog_address,
            http_url,
            debug,
            "bash",
        )
        .await;
    });

    Ok(())
}

/// Handle zsh zlentry monitoring
pub async fn setup_zsh_monitoring(
    ebpf: &mut LoadedEbpf,
    config: &AppConfig,
    output: &OutputConfig,
) -> Result<()> {
    let binary_path = find_binary("/bin/zsh")?;
    attach_uprobe(&mut ebpf.ebpf, "zlentry", "zleentry", &binary_path)?;

    let async_fd = create_ring_buffer_async_fd(&mut ebpf.ebpf, "zlentry_events")?;

    let executables = config.executables.clone();
    let client = output.client.clone();
    let hostname = output.hostname.clone();
    let json = config.json;
    let http = config.http;
    let syslog = config.syslog;
    let syslog_address = output.syslog_address.clone();
    let http_url = output.http_url.clone();
    let debug = config.debug;

    tokio::spawn(async move {
        consume_shell_events(
            client,
            async_fd,
            executables,
            hostname,
            json,
            http,
            syslog,
            syslog_address,
            http_url,
            debug,
            "zsh",
        )
        .await;
    });

    Ok(())
}

/// Find and canonicalize a binary path
fn find_binary(name: &str) -> Result<String> {
    let path = PathBuf::from(name);
    let canonical = path
        .canonicalize()
        .map_err(|_| PanhandleError::InvalidArgument(format!("Could not find {}", name)))?;

    if !canonical.exists() {
        return Err(PanhandleError::InvalidArgument(format!(
            "Binary not found: {}",
            name
        )));
    }

    canonical.into_os_string().into_string().map_err(|_| {
        PanhandleError::InvalidArgument(format!("Path to {} is not valid UTF-8", name))
    })
}

/// Consume shell events from ring buffer
async fn consume_shell_events(
    client: Client,
    mut async_fd: tokio::io::unix::AsyncFd<aya::maps::RingBuf<aya::maps::MapData>>,
    executable_vec: Vec<String>,
    hostname: Arc<String>,
    json: bool,
    http: bool,
    _syslog: bool,
    _syslog_address: Arc<String>,
    http_url: Arc<String>,
    _debug: bool,
    shell_type: &str,
) {
    use crate::helpers::read_ring_item;
    use panhandle_common::Readline;

    loop {
        let Ok(mut guard) = async_fd.ready_mut(Interest::READABLE).await else {
            continue;
        };

        let ring_buf = guard.get_inner_mut();
        while let Some(item) = ring_buf.next() {
            let event: Readline = unsafe { read_ring_item(&item) };

            // Filter by executable if specified
            if !executable_vec.is_empty() {
                let comm = std::str::from_utf8(&event.command)
                    .unwrap_or_default()
                    .trim_end_matches('\0')
                    .trim();
                if !executable_vec.iter().any(|e| e == comm) {
                    continue;
                }
            }

            // Format output
            let entry = std::str::from_utf8(&event.entry)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim();

            let command = std::str::from_utf8(&event.command)
                .unwrap_or_default()
                .trim_end_matches('\0')
                .trim();

            let timestamp = chrono::DateTime::<chrono::Utc>::from_timestamp(
                (event.timestamp as i64) / 1_000_000_000,
                0,
            )
            .unwrap_or_default();

            let ts_utc = timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
            let ts_local = chrono::DateTime::<chrono::Local>::from(timestamp)
                .format("%Y-%m-%d %H:%M:%S%.3f")
                .to_string();

            let json_payload = serde_json::json!({
                "timestamp": ts_utc,
                "hostname": hostname.as_str(),
                "type": "shell",
                "shell_type": shell_type,
                "uid": event.uid,
                "gid": event.gid,
                "pid": event.pid,
                "tgid": event.tgid,
                "command": command,
                "entry": entry,
            })
            .to_string();

            let text_payload = format!("{} [{}]: {} ({})", ts_local, shell_type, command, entry,);

            // Console output
            if json {
                println!("{}", json_payload);
            } else {
                println!("{}", text_payload);
            }

            // HTTP output
            if http {
                let _ = client
                    .post(http_url.as_str())
                    .header("Content-Type", "application/json")
                    .body(json_payload.clone())
                    .send()
                    .await;
            }
        }

        guard.clear_ready();
    }
}
