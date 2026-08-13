use std::{collections::HashMap, sync::Arc};

use machine_info::Machine;
use reqwest::Client;

use crate::helpers::*;

/*
Monitors gpu usage per pid and globally per gpu
Two output messages:
Per process messages contain:
- PID
- Comm (process name)
- PPID (if verbose)
- Parent_Comm (if verbose)
- GPU ID
- VRAM usage as percentage
- Encoder/Decoder usage

Per GPU messages contain:
- GPU ID
- GPU utilization percentage
- VRAM usage as percentage
- VRAM usage in bytes
- Encoder/Decoder usage
- Temperature
*/

// Fully-owned per-process GPU data gathered during the blocking scan phase.
struct GpuProcessEntry {
    pid: u32,
    comm: String,
    ppid: Option<u32>,
    parent_comm: Option<String>,
    uid: Option<u32>,
    username: Option<String>,
    gpu_id: u32,
    vram_percent: u32,
    encoder_percent: u32,
    decoder_percent: u32,
}

// Fully-owned per-GPU data gathered during the blocking scan phase.
struct GpuEntry {
    id: String,
    gpu_percent: u32,
    vram_percent: u32,
    vram_mb: u64,
    encoder_percent: u32,
    decoder_percent: u32,
    temperature: u32,
    processes: Vec<GpuProcessEntry>,
}

pub async fn monitor_gpu_usage(
    machine: &Machine,
    json_output: &bool,
    http: &bool,
    syslog: &bool,
    debug: &bool,
    verbose: &bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    global_url: &Arc<String>,
    client: &Client,
    pid_list: &Option<Vec<u32>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (needs_plain, needs_json) = output_needs(*http, *syslog, *json_output, *debug);

    // Gather the NVML query and procfs lookups up front (off the async executor) so the
    // reporting loop below only does formatting/output work.
    let gpus: Vec<GpuEntry> = tokio::task::block_in_place(|| {
        let mut gpus = Vec::new();
        // Cache of uid -> username, scoped to this single poll, so N processes owned by
        // the same user cost one username lookup instead of N when --verbose is set --
        // this can hit network-backed NSS (LDAP).
        let mut username_cache: HashMap<u32, String> = HashMap::new();

        for gpu in machine.graphics_status() {
            let mut processes = Vec::new();

            for process in gpu.processes {
                if let Some(pids) = pid_list
                    && !pids.contains(&{ process.pid })
                {
                    continue;
                }

                let comm = if process.pid > 0 {
                    get_process_name(process.pid).unwrap_or_else(|| "unknown".to_string())
                } else {
                    "unknown".to_string()
                };

                // Retrieve parent process info only if verbose flag is set
                let (ppid, parent_comm) = if *verbose {
                    if let Ok(parent_pid) = get_parent_pid(process.pid) {
                        let parent_name =
                            get_process_name(parent_pid).unwrap_or_else(|| "unknown".to_string());
                        (Some(parent_pid), Some(parent_name))
                    } else {
                        (Some(0), Some("unknown".to_string()))
                    }
                } else {
                    (None, None)
                };

                // Retrieve owner info only if verbose flag is set
                let (uid, username) = if *verbose && process.pid > 0 {
                    match get_process_uid(process.pid) {
                        Some(uid) => {
                            let username = username_cache
                                .entry(uid)
                                .or_insert_with(|| resolve_username(uid))
                                .clone();
                            (Some(uid), Some(username))
                        }
                        None => (None, Some("unknown".to_string())),
                    }
                } else {
                    (None, None)
                };

                processes.push(GpuProcessEntry {
                    pid: process.pid,
                    comm,
                    ppid,
                    parent_comm,
                    uid,
                    username,
                    gpu_id: process.gpu,
                    vram_percent: process.memory,
                    encoder_percent: process.encoder,
                    decoder_percent: process.decoder,
                });
            }

            gpus.push(GpuEntry {
                id: gpu.id,
                gpu_percent: gpu.gpu,
                vram_percent: gpu.memory_usage,
                vram_mb: gpu.memory_used / (1024 * 1024),
                encoder_percent: gpu.encoder,
                decoder_percent: gpu.decoder,
                temperature: gpu.temperature,
                processes,
            });
        }

        gpus
    });

    for gpu in gpus {
        for process in gpu.processes {
            let (plain_string, json_string) = if *verbose {
                let ppid_val = process.ppid.unwrap_or(0);
                let parent_comm_val = process.parent_comm.as_deref().unwrap_or("unknown");
                let (uid_val, username_val) =
                    format_owner(process.uid, process.username.as_deref());

                let plain = if needs_plain {
                    format!(
                        "Type: gpu, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, UID: {}, Username: {}, GPU_ID: {}, VRAM_Percent: {}, Encoder_Percent: {}, Decoder_Percent: {}",
                        process.pid,
                        process.comm,
                        ppid_val,
                        parent_comm_val,
                        uid_val,
                        username_val,
                        process.gpu_id,
                        process.vram_percent,
                        process.encoder_percent,
                        process.decoder_percent
                    )
                } else {
                    String::new()
                };

                let json = if needs_json {
                    format!(
                        "{{\"Type\": \"gpu\", \"PID\": {}, \"Comm\": \"{}\", \"PPID\": {}, \"Parent_Comm\": \"{}\", \"UID\": \"{}\", \"Username\": \"{}\", \"GPU_ID\": {}, \"VRAM_Percent\": {}, \"Encoder_Percent\": {}, \"Decoder_Percent\": {}}}",
                        process.pid,
                        process.comm,
                        ppid_val,
                        parent_comm_val,
                        uid_val,
                        username_val,
                        process.gpu_id,
                        process.vram_percent,
                        process.encoder_percent,
                        process.decoder_percent
                    )
                } else {
                    String::new()
                };

                (plain, json)
            } else {
                let plain = if needs_plain {
                    format!(
                        "Type: gpu, PID: {}, Comm: {}, GPU_ID: {}, VRAM_Percent: {}, Encoder_Percent: {}, Decoder_Percent: {}",
                        process.pid,
                        process.comm,
                        process.gpu_id,
                        process.vram_percent,
                        process.encoder_percent,
                        process.decoder_percent
                    )
                } else {
                    String::new()
                };

                let json = if needs_json {
                    format!(
                        "{{\"Type\": \"gpu\", \"PID\": {}, \"Comm\": \"{}\", \"GPU_ID\": {}, \"VRAM_Percent\": {}, \"Encoder_Percent\": {}, \"Decoder_Percent\": {}}}",
                        process.pid,
                        process.comm,
                        process.gpu_id,
                        process.vram_percent,
                        process.encoder_percent,
                        process.decoder_percent
                    )
                } else {
                    String::new()
                };

                (plain, json)
            };

            output_message(
                http,
                syslog,
                hostname,
                syslog_address,
                global_url,
                json_output,
                &plain_string,
                &json_string,
                client,
                debug,
            )
            .await;
        }

        // construct the global (per gpu) messages
        let plain_string = if needs_plain {
            format!(
                "Type: gpu, GPU_ID: {}, GPU_Percent: {}, VRAM_Percent: {}, VRAM_MB: {}, Encoder_Percent: {}, Decoder_Percent: {}, Temperature_C: {}",
                gpu.id,
                gpu.gpu_percent,
                gpu.vram_percent,
                gpu.vram_mb,
                gpu.encoder_percent,
                gpu.decoder_percent,
                gpu.temperature
            )
        } else {
            String::new()
        };
        let json_string = if needs_json {
            format!(
                "{{\"Type\": \"gpu\", \"GPU_ID\": {}, \"GPU_Percent\": {}, \"VRAM_Percent\": {}, \"VRAM_MB\": {}, \"Encoder_Percent\": {}, \"Decoder_Percent\": {}, \"Temperature_C\": {}}}",
                gpu.id,
                gpu.gpu_percent,
                gpu.vram_percent,
                gpu.vram_mb,
                gpu.encoder_percent,
                gpu.decoder_percent,
                gpu.temperature
            )
        } else {
            String::new()
        };

        output_message(
            http,
            syslog,
            hostname,
            syslog_address,
            global_url,
            json_output,
            &plain_string,
            &json_string,
            client,
            debug,
        )
        .await;
    }
    Ok(())
}
