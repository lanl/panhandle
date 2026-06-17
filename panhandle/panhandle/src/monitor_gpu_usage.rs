use std::sync::Arc;

use machine_info::Machine; // main crate used for reading gpu utilization
use reqwest::Client;

use crate::helpers::*;
/*
Monitors gpu usage per pid and globally per gpu
Two output messages:
Per process messages contain:
- PID
- Comm (process name)
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
            let comm = if process.pid > 0 {
                get_process_name(process.pid).unwrap_or_else(|| "unknown".to_string())
            } else {
                "unknown".to_string()
            };
            // construct output strings containing PID info
            let plain_string = format!("PID: {}, Comm: {}, GPU_ID: {}, VRAM%: {}, Encoder%: {}, Decoder%: {}", 
                process.pid, comm, process.gpu, process.memory, process.encoder, process.decoder);
            let json_string = format!(
                "{{\"PID\": {}, \"Comm\": \"{}\", \"GPU_ID\": {}, \"VRAM%\": {}, \"Encoder%\": {}, \"Decoder%\": {}}}",
                process.pid, comm, process.gpu, process.memory, process.encoder, process.decoder
            );

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
            "GPU_ID: {}, GPU%: {}, VRAM%: {}, VRAM_Bytes: {}, Encoder%: {}, Decoder%: {}, Temperature: {}°C",
            gpu.id, gpu.gpu, gpu.memory_usage, gpu.memory_used, gpu.encoder, gpu.decoder, gpu.temperature
        );
        let json_string = format!(
            "{{\"GPU_ID\": {}, \"GPU%\": {}, \"VRAM%\": {}, \"VRAM_Bytes\": {}, \"Encoder%\": {}, \"Decoder%\": {}, \"Temperature\": \"{}°C\"}}",
            gpu.id, gpu.gpu, gpu.memory_usage, gpu.memory_used, gpu.encoder, gpu.decoder, gpu.temperature
        );

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