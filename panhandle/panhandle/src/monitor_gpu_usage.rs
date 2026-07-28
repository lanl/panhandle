use std::sync::Arc;

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
    for gpu in machine.graphics_status() {
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

            let (plain_string, json_string) = if *verbose {
                let ppid_val = ppid.unwrap_or(0);
                let parent_comm_val = parent_comm.as_deref().unwrap_or("unknown");

                let plain = format!(
                    "Type: gpu, PID: {}, Comm: {}, PPID: {}, Parent_Comm: {}, GPU_ID: {}, VRAM_Percent: {}, Encoder_Percent: {}, Decoder_Percent: {}",
                    process.pid,
                    comm,
                    ppid_val,
                    parent_comm_val,
                    process.gpu,
                    process.memory,
                    process.encoder,
                    process.decoder
                );

                let json = format!(
                    "{{\"Type\": \"gpu\", \"PID\": {}, \"Comm\": \"{}\", \"PPID\": {}, \"Parent_Comm\": \"{}\", \"GPU_ID\": {}, \"VRAM_Percent\": {}, \"Encoder_Percent\": {}, \"Decoder_Percent\": {}}}",
                    process.pid,
                    comm,
                    ppid_val,
                    parent_comm_val,
                    process.gpu,
                    process.memory,
                    process.encoder,
                    process.decoder
                );

                (plain, json)
            } else {
                let plain = format!(
                    "Type: gpu, PID: {}, Comm: {}, GPU_ID: {}, VRAM_Percent: {}, Encoder_Percent: {}, Decoder_Percent: {}",
                    process.pid,
                    comm,
                    process.gpu,
                    process.memory,
                    process.encoder,
                    process.decoder
                );

                let json = format!(
                    "{{\"Type\": \"gpu\", \"PID\": {}, \"Comm\": \"{}\", \"GPU_ID\": {}, \"VRAM_Percent\": {}, \"Encoder_Percent\": {}, \"Decoder_Percent\": {}}}",
                    process.pid,
                    comm,
                    process.gpu,
                    process.memory,
                    process.encoder,
                    process.decoder
                );

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
        let vram_mb = gpu.memory_used / (1024 * 1024);

        let plain_string = format!(
            "Type: gpu, GPU_ID: {}, GPU_Percent: {}, VRAM_Percent: {}, VRAM_MB: {}, Encoder_Percent: {}, Decoder_Percent: {}, Temperature_C: {}",
            gpu.id, gpu.gpu, gpu.memory_usage, vram_mb, gpu.encoder, gpu.decoder, gpu.temperature
        );
        let json_string = format!(
            "{{\"Type\": \"gpu\", \"GPU_ID\": {}, \"GPU_Percent\": {}, \"VRAM_Percent\": {}, \"VRAM_MB\": {}, \"Encoder_Percent\": {}, \"Decoder_Percent\": {}, \"Temperature_C\": {}}}",
            gpu.id, gpu.gpu, gpu.memory_usage, vram_mb, gpu.encoder, gpu.decoder, gpu.temperature
        );

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
