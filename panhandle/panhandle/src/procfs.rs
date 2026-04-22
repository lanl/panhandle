use procfs::process::all_processes;
use simplelog::*;

/*
/*
    Method to return all information procfs finds about all processes.
    Takes no input parameters.
    Use for debugging only.
*/
pub fn get_all_proc_info() {
    if let Ok(procs) = all_processes() {
        for proc_res in procs {
            if let Ok(p) = proc_res
                && let Ok(stat) = p.stat()
            {
                // This prints the following example:
                //14:27:35 [INFO] panhandle::procfs: [panhandle/src/procfs.rs:10] Stat { pid: 395900, comm: "sudo", state: 'S', ppid: 395435, pgrp: 395900,
                //session: 395900, tty_nr: 34817, tpgid: 395901, flags: 4194368, minflt: 47, cminflt: 0, majflt: 0, cmajflt: 0, utime: 0, stime: 0, cutime: 0,
                //cstime: 0, priority: 20, nice: 0, num_threads: 1, itrealvalue: 0, starttime: 8616530, vsize: 153325568, rss: 267, rsslim: 18446744073709551615,
                //startcode: 94800910770176, endcode: 94800910944616, startstack: 140726370712480, kstkesp: 0, kstkeip: 0, signal: 0, blocked: 0, sigignore: 3149824,
                //sigcatch: 616967, wchan: 1, nswap: 0, cnswap: 0, exit_signal: Some(17), processor: Some(10), rt_priority: Some(0), policy: Some(0),
                //delayacct_blkio_ticks: Some(0), guest_time: Some(0), cguest_time: Some(0), start_data: Some(94800913045008), end_data: Some(94800913052000),
                //start_brk: Some(94800922886144), arg_start: Some(140726370718480), arg_end: Some(140726370718511), env_start: Some(140726370718511),
                //env_end: Some(140726370725866), exit_code: Some(0) }
                info!("{:?}", stat);
            }
        }
    }
}
*/

/*
    Method to check if processes or their children have memory faults greater than a certain threshold.
    Takes the desired threshold as an input parameter.
*/
pub fn get_major_faults(maj_fault_threshold: u64) {
    // Get an iterator over all processes in /proc
    if let Ok(procs) = all_processes() {
        for proc_res in procs.flatten() {
            // Read /proc/[pid]/stat for this process
            if let Ok(stat) = proc_res.stat()
                && (stat.majflt > maj_fault_threshold || stat.cmajflt > maj_fault_threshold)
            {
                info!(
                    "PID: {}, Comm: {}, Major Faults: {}, Child Major Faults: {},",
                    stat.pid, stat.comm, stat.majflt, stat.cmajflt
                );
            }
        }
    }
}
