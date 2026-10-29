use crate::error::{PanhandleError, Result};
use chrono::{DateTime, Local, Utc};
use panhandle_common::{ExecveEvent, Readline};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use syslog::{Facility, Formatter3164};

/// Output configuration for formatting and sending events
#[derive(Debug, Clone)]
pub struct OutputConfig {
    pub hostname: Arc<String>,
    pub json: bool,
    pub http: bool,
    pub syslog: bool,
    pub syslog_address: Arc<String>,
    pub http_url: Arc<String>,
    pub debug: bool,
    pub client: Client,
}

impl OutputConfig {
    pub fn new(
        hostname: Arc<String>,
        json: bool,
        http: bool,
        syslog: bool,
        syslog_address: Arc<String>,
        http_url: Arc<String>,
        debug: bool,
        client: Client,
    ) -> Result<Self> {
        Ok(Self {
            hostname,
            json,
            http,
            syslog,
            syslog_address,
            http_url,
            debug,
            client,
        })
    }

    /// Format a shell event (readline/zlentry) as JSON
    #[allow(dead_code)]
    pub fn format_shell_event_json(&self, event: &Readline, moniker: &str) -> String {
        let timestamp =
            DateTime::<Utc>::from_timestamp((event.timestamp as i64) / 1_000_000_000, 0)
                .unwrap_or_default();

        let ts_utc = timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let entry = std::str::from_utf8(&event.entry)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();

        let command = std::str::from_utf8(&event.command)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();

        json!({
            "timestamp": ts_utc,
            "hostname": self.hostname.as_str(),
            "type": "shell",
            "shell_type": moniker,
            "uid": event.uid,
            "gid": event.gid,
            "pid": event.pid,
            "tgid": event.tgid,
            "command": command,
            "entry": entry,
        })
        .to_string()
    }

    /// Format an execve event as JSON
    pub fn format_execve_event_json(&self, event: &ExecveEvent, moniker: &str) -> String {
        let timestamp =
            DateTime::<Utc>::from_timestamp((event.timestamp as i64) / 1_000_000_000, 0)
                .unwrap_or_default();

        let ts_utc = timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let filename = std::str::from_utf8(&event.filename)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();

        let command = std::str::from_utf8(&event.command)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();

        let args: Vec<String> = event
            .argv
            .iter()
            .filter_map(|arg| {
                let s = std::str::from_utf8(arg).ok()?.trim_end_matches('\0').trim();
                if s.is_empty() || s.starts_with('\0') {
                    None
                } else {
                    Some(s.to_string())
                }
            })
            .collect();

        let envs: Vec<String> = event
            .envp
            .iter()
            .filter_map(|env| {
                let s = std::str::from_utf8(env).ok()?.trim_end_matches('\0').trim();
                if s.is_empty() || s.starts_with('\0') {
                    None
                } else {
                    Some(s.to_string())
                }
            })
            .collect();

        json!({
            "timestamp": ts_utc,
            "hostname": self.hostname.as_str(),
            "type": "execve",
            "monitor": moniker,
            "uid": event.uid,
            "gid": event.gid,
            "pid": event.pid,
            "tgid": event.tgid,
            "command": command,
            "filename": filename,
            "args": args,
            "envs": envs,
        })
        .to_string()
    }

    /// Format a shell event as text
    #[allow(dead_code)]
    pub fn format_shell_event_text(&self, event: &Readline, moniker: &str) -> String {
        let timestamp_utc =
            DateTime::<Utc>::from_timestamp((event.timestamp as i64) / 1_000_000_000, 0)
                .unwrap_or_default();
        let timestamp = DateTime::<Local>::from(timestamp_utc);

        let ts_local = timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string();

        let entry = std::str::from_utf8(&event.entry)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();

        let command = std::str::from_utf8(&event.command)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();

        format!(
            "{} [{}] {}: {} ({})",
            ts_local, moniker, command, entry, event.uid
        )
    }

    /// Format an execve event as text
    pub fn format_execve_event_text(&self, event: &ExecveEvent, moniker: &str) -> String {
        let timestamp_utc =
            DateTime::<Utc>::from_timestamp((event.timestamp as i64) / 1_000_000_000, 0)
                .unwrap_or_default();
        let timestamp = DateTime::<Local>::from(timestamp_utc);

        let ts_local = timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string();

        let filename = std::str::from_utf8(&event.filename)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();

        let command = std::str::from_utf8(&event.command)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .trim();

        let args: Vec<String> = event
            .argv
            .iter()
            .filter_map(|arg| {
                let s = std::str::from_utf8(arg).ok()?.trim_end_matches('\0').trim();
                if s.is_empty() || s.starts_with('\0') {
                    None
                } else {
                    Some(s.to_string())
                }
            })
            .collect();

        format!(
            "{} [{}] {}: filename={}, args={:?}, uid={}",
            ts_local, moniker, command, filename, args, event.uid
        )
    }

    /// Send event to HTTP endpoint
    pub async fn send_http(&self, payload: &str) -> Result<()> {
        if !self.http {
            return Ok(());
        }

        let response = self
            .client
            .post(self.http_url.as_str())
            .header("Content-Type", "application/json")
            .body(payload.to_string())
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => Err(PanhandleError::HttpStatus(format!(
                "HTTP error: {}",
                resp.status()
            ))),
            Err(e) => Err(PanhandleError::HttpRequest(e)),
        }
    }

    /// Send event to syslog
    pub fn send_syslog(&self, message: &str) -> Result<()> {
        if !self.syslog {
            return Ok(());
        }

        // Create syslog writer based on address
        let formatter = Formatter3164 {
            facility: Facility::LOG_USER,
            hostname: Some(self.hostname.as_str().to_string()),
            process: "panhandle".into(),
            pid: std::process::id(),
        };

        let mut writer = if self.syslog_address.as_str().starts_with("unix")
            || self.syslog_address.as_str() == "/dev/log"
        {
            syslog::unix(formatter).map_err(PanhandleError::Syslog)?
        } else if self.syslog_address.as_str().starts_with("udp://") {
            let addr = self.syslog_address.trim_start_matches("udp://");
            syslog::udp(formatter, "0.0.0.0:0", addr.to_string()).map_err(PanhandleError::Syslog)?
        } else if self.syslog_address.as_str().starts_with("tcp://") {
            let addr = self.syslog_address.trim_start_matches("tcp://");
            syslog::tcp(formatter, addr.to_string()).map_err(PanhandleError::Syslog)?
        } else {
            // Default to local unix syslog
            syslog::unix(formatter).map_err(PanhandleError::Syslog)?
        };

        // Use block_in_place since syslog writes are synchronous
        tokio::task::block_in_place(|| writer.info(message).map_err(PanhandleError::Syslog))?;

        Ok(())
    }

    /// Output an event (console, HTTP, syslog)
    pub async fn output_event(&self, json_payload: &str, text_payload: &str) -> Result<()> {
        // Console output
        if self.json {
            println!("{}", json_payload);
        } else {
            println!("{}", text_payload);
        }

        // HTTP output
        if self.http {
            self.send_http(json_payload).await?;
        }

        // Syslog output
        if self.syslog {
            self.send_syslog(text_payload)?;
        }

        Ok(())
    }
}
