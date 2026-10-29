use crate::config::{PanhandleConfig, ShellConfig};
use crate::error::{PanhandleError, Result};
use aya::{
    Btf, EbpfLoader, VerifierLogLevel,
    maps::RingBuf,
    programs::{BtfTracePoint, RawTracePoint, UProbe, uprobe::UProbeScope},
};
use aya_log::EbpfLogger;
use tokio::io::{Interest, unix::AsyncFd};

/// Loaded eBPF programs and maps
pub struct LoadedEbpf {
    pub ebpf: aya::Ebpf,
    pub btf: Option<Btf>,
}

/// Load and configure the eBPF program with GlobalData
pub fn load_ebpf(
    debug: bool,
    panhandle_config: &PanhandleConfig,
    shell_config: &ShellConfig,
) -> Result<LoadedEbpf> {
    let ebpf_bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panhandle"));

    let mut loader = EbpfLoader::new();

    // Enable verifier logs in debug mode
    if debug {
        loader.verifier_log_level(VerifierLogLevel::DEBUG);
    }

    // Set GlobalData for panhandle (execve) configuration
    loader.override_global("PANHANDLE_CONFIG", panhandle_config, true);

    // Set GlobalData for shell (readline/zlentry) configuration
    loader.override_global("SHELL_CONFIG", shell_config, true);

    let mut ebpf = loader.load(ebpf_bytes).map_err(PanhandleError::EbpfLoad)?;

    // Initialize eBPF logger if debug enabled
    if debug {
        match EbpfLogger::init(&mut ebpf) {
            Ok(logger) => {
                let mut async_logger =
                    unsafe { AsyncFd::register_with_interest(logger, Interest::READABLE) }
                        .map_err(|e| PanhandleError::AsyncFd(e.to_string()))?;
                tokio::spawn(async move {
                    loop {
                        let Ok(mut guard) = async_logger.ready_mut(Interest::READABLE).await else {
                            continue;
                        };
                        guard.get_inner_mut().flush();
                        guard.clear_ready();
                    }
                });
            }
            Err(e) => eprintln!("failed to initialize eBPF logger: {e}"),
        }
    }

    // Load BTF for BTF tracepoints
    let btf = Btf::from_sys_fs().ok();

    Ok(LoadedEbpf { ebpf, btf })
}

/// Attach a raw tracepoint
pub fn attach_raw_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    tracepoint_name: &str,
) -> Result<()> {
    let program: &mut RawTracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(PanhandleError::EbpfAttach)?;

    program.load().map_err(PanhandleError::EbpfAttach)?;
    program
        .attach(tracepoint_name)
        .map_err(PanhandleError::EbpfAttach)?;

    Ok(())
}

/// Attach a BTF tracepoint
pub fn attach_btf_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    tracepoint_name: &str,
    btf: &Btf,
) -> Result<()> {
    let program: &mut BtfTracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(PanhandleError::EbpfAttach)?;

    program
        .load(tracepoint_name, btf)
        .map_err(PanhandleError::EbpfAttach)?;
    program.attach().map_err(PanhandleError::EbpfAttach)?;

    Ok(())
}

/// Attach a uprobe
pub fn attach_uprobe(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    attach_point: &str,
    binary_path: &str,
) -> Result<()> {
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(PanhandleError::EbpfAttach)?;

    program.load().map_err(PanhandleError::EbpfAttach)?;
    program
        .attach([attach_point], binary_path, UProbeScope::AllProcesses)
        .map_err(PanhandleError::EbpfAttach)?;

    Ok(())
}

/// Attach a kprobe
pub fn attach_kprobe(ebpf: &mut aya::Ebpf, program_name: &str) -> Result<()> {
    use aya::programs::KProbe;

    let program: &mut KProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(PanhandleError::EbpfAttach)?;

    program.load().map_err(PanhandleError::EbpfAttach)?;
    // KProbe attach requires the function name - use program_name as the function to trace
    program
        .attach(program_name, 0)
        .map_err(PanhandleError::EbpfAttach)?;

    Ok(())
}

/// Attach an LSM hook
pub fn attach_lsm_hook(
    ebpf: &mut aya::Ebpf,
    hook_name: &str,
    program_name: &str,
    btf: &Btf,
) -> Result<()> {
    use aya::programs::Lsm;

    let program: &mut Lsm = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(PanhandleError::EbpfAttach)?;

    program
        .load(hook_name, btf)
        .map_err(PanhandleError::EbpfAttach)?;
    program.attach().map_err(PanhandleError::EbpfAttach)?;

    Ok(())
}

/// Create an AsyncFd for a ring buffer map
pub fn create_ring_buffer_async_fd(
    ebpf: &mut aya::Ebpf,
    map_name: &str,
) -> Result<AsyncFd<RingBuf<aya::maps::MapData>>> {
    let ring_buf = RingBuf::try_from(
        ebpf.take_map(map_name)
            .ok_or_else(|| PanhandleError::MissingMap(map_name.to_string()))?,
    )
    .map_err(PanhandleError::EbpfMap)?;

    unsafe { AsyncFd::register_with_interest(ring_buf, Interest::READABLE) }
        .map_err(|e| PanhandleError::AsyncFd(e.to_string()))
}

/// Get a HashMap from the eBPF maps
pub fn get_hash_map<K, V>(
    ebpf: &mut aya::Ebpf,
    map_name: &str,
) -> Result<aya::maps::HashMap<aya::maps::MapData, K, V>>
where
    K: aya::Pod + Send + Sync + 'static,
    V: aya::Pod + Send + Sync + 'static,
{
    let map = ebpf
        .take_map(map_name)
        .ok_or_else(|| PanhandleError::MissingMap(map_name.to_string()))?;

    aya::maps::HashMap::try_from(map).map_err(PanhandleError::EbpfMap)
}
