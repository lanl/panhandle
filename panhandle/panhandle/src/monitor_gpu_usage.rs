use std::sync::Arc;

use machine_info::Machine; // main crate used for reading gpu utilization
use reqwest::Client;
use serde_json::json;

use crate::helpers::output_message;
/*
Monitors gpu usage per pid and globally per gpu
Two output messages:
Per process messages contain:
- PID
- GPU ID
- VRAM usage as percentage
- VRAM usage in bytes
- Encoder/Decoder usage

Per GPU messages contain:
- GPU ID
- GPU utilization percentage
- VRAM usage as percentage
- VRAM usage in bytes
- Encoder/Decoder usage
- Temperature
*/
pub async fn monitor_gpu_usage (
    machine: &Machine,
    json_output: &bool,
    http: &bool,
    syslog: &bool,
    debug: &bool,
    hostname: &Arc<String>,
    syslog_address: &Arc<String>,
    global_url: &Arc<String>,
    client: &Client,
    pid_list: &Option<Vec<u32>>) -> Result<(), Box<dyn std::error::Error>> {
    
    // graphics usage contains per computer gpu information
    for gpu in machine.graphics_status() {
        // GraphicsProcessUtilization contains per process gpu utilization
        for process in gpu.processes {
            // apply PID filter if provided
            if let Some(pids) = pid_list
                && !pids.contains(&(process.pid as u32))
            {
                continue;
            }
            // construct output strings containing PID info
            let plain_string = format!("PID: {}, GPU: {}, VRAM_Usage: {}%, Encoder: {}%, Decoder: {}%", process.pid, process.gpu, process.memory, process.encoder, process.decoder);
            let json_value = json!({
                "PID": process.pid,
                "GPU": process.gpu,
                "VRAM_Usage": process.memory,
                "Encoder": process.encoder,
                "Decoder": process.decoder
            });
            let json_string = json_value.to_string();

            // output the per pid message
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
        
        // now construct the global (per gpu) messages
        let plain_string = format!(
            "GPU_ID: {}, GPU_Utilization: {}%, VRAM_Usage: {}%, VRAM_Used: {} bytes, Encoder: {}%, Decoder: {}%, Temperature: {} Celsius",
            gpu.id, gpu.gpu, gpu.memory_usage, gpu.memory_used, gpu.encoder, gpu.decoder, gpu.temperature
        );
        let json_value = json!({
            "GPU_ID": gpu.id,
            "GPU_Utilization": gpu.gpu,
            "VRAM_Usage": gpu.memory_usage,
            "VRAM_Used": gpu.memory_used,
            "Encoder": gpu.encoder,
            "Decoder": gpu.decoder,
            "Temperature": gpu.temperature
        });
        let json_string = json_value.to_string();

        // output the per gpu message
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