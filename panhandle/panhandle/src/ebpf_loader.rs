use crate::btf_offsets::{KERNEL_BTF_PATH, struct_member_offset};
use crate::config::PanhandleConfig;
use crate::error::{PanhandleError, Result};
use aya::{
    Btf, EbpfLoader, Endianness, VerifierLogLevel,
    maps::RingBuf,
    programs::{
        BtfTracePoint, FEntry, FExit, RawTracePoint, TracePoint, UProbe, uprobe::UProbeScope,
    },
};
use aya_log::EbpfLogger;
use panhandle_common::{
    UID_OPT_EXCLUDE_MAX, UID_OPT_EXCLUDE_MIN, UID_OPT_INCLUDE_ENABLED, UID_OPT_SHELLS,
};
use tokio::io::{Interest, unix::AsyncFd};

/// What the requested features need from the kernel's BTF (several MB to read and
/// parse); nothing is read unless something needs it.
#[derive(Clone, Copy, Debug, Default)]
pub struct BtfNeeds {
    /// BTF-based programs will be attached: --socket, --bound, --syscalls
    pub programs: bool,
    /// open/openat/creat blocking needs struct file's f_path offset
    pub file_f_path_offset: bool,
}

/// Loaded eBPF programs and maps
pub struct LoadedEbpf {
    pub ebpf: aya::Ebpf,
    pub btf: Option<Btf>,
}

/// Load the eBPF program and populate the UID-filtering maps of the execve,
/// readline, and zlentry programs from `uid_config`. These are runtime-configurable
/// maps rather than load-time GlobalData so they can still be adjusted after load.
///
/// Kernel BTF is only read if `btf_needs` asks for it, and then only once: the same
/// bytes give the parsed `Btf` returned for attaching BTF-based programs and, for
/// open/openat/creat blocking, `struct file`'s `f_path` offset - injected as the
/// `FILE_F_PATH_OFFSET` load-time global (left at 0 otherwise; the open-blocking
/// programs are then never loaded, so it's never used).
pub fn load_ebpf(
    debug: bool,
    uid_config: &PanhandleConfig,
    btf_needs: BtfNeeds,
) -> Result<LoadedEbpf> {
    let ebpf_bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/panhandle"));

    let btf_bytes = if btf_needs.programs || btf_needs.file_f_path_offset {
        std::fs::read(KERNEL_BTF_PATH).ok()
    } else {
        None
    };
    let file_f_path_offset = if btf_needs.file_f_path_offset {
        btf_bytes
            .as_deref()
            .ok_or_else(|| format!("could not read kernel BTF at {KERNEL_BTF_PATH}"))
            .and_then(|bytes| struct_member_offset(bytes, "file", "f_path"))
            .map_err(|e| {
                log::error!(
                    "--syscalls open/openat/creat needs kernel BTF to locate struct file's f_path: {e}"
                );
                PanhandleError::BtfUnavailable(e)
            })?
    } else {
        0
    };
    let btf = if btf_needs.programs {
        btf_bytes
            .as_deref()
            .and_then(|bytes| Btf::parse(bytes, Endianness::default()).ok())
    } else {
        None
    };
    drop(btf_bytes);

    let mut ebpf = {
        let mut loader = EbpfLoader::new();
        loader.override_global("FILE_F_PATH_OFFSET", &file_f_path_offset, true);
        // aya only parses target BTF itself for objects with CO-RE relocations; hand it
        // ours so that never means a second parse
        if let Some(btf) = &btf {
            loader.btf(btf);
        }
        // Enable verifier logs in debug mode
        if debug {
            loader.verifier_log_level(VerifierLogLevel::DEBUG);
        }
        loader.load(ebpf_bytes).map_err(PanhandleError::EbpfLoad)?
    };

    // Populate the execve, readline, and zlentry programs' UID filtering maps
    for (options_map, include_list_map) in [
        ("uid_options", "uid_include_list"),
        ("readline_uid_options", "readline_uid_include_list"),
        ("zlentry_uid_options", "zlentry_uid_include_list"),
    ] {
        set_uid_options(&mut ebpf, options_map, include_list_map, uid_config)?;
    }

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

    Ok(LoadedEbpf { ebpf, btf })
}

/// Populate a `uid_options`/`uid_include_list`-shaped pair of maps.
fn set_uid_options(
    ebpf: &mut aya::Ebpf,
    options_map: &str,
    include_list_map: &str,
    uid_config: &PanhandleConfig,
) -> Result<()> {
    let mut options: aya::maps::HashMap<_, u32, u32> = get_hash_map_mut(ebpf, options_map)?;
    for (key, value) in [
        (UID_OPT_SHELLS, uid_config.shells),
        (UID_OPT_EXCLUDE_MIN, uid_config.exclude_min_uid),
        (UID_OPT_EXCLUDE_MAX, uid_config.exclude_max_uid),
        (UID_OPT_INCLUDE_ENABLED, uid_config.include_enabled),
    ] {
        options
            .insert(&key, &value, 0)
            .map_err(PanhandleError::EbpfMap)?;
    }

    let mut include_list: aya::maps::HashMap<_, u32, [u32; panhandle_common::UID_COUNT]> =
        get_hash_map_mut(ebpf, include_list_map)?;
    include_list
        .insert(&0, &uid_config.include_uids, 0)
        .map_err(PanhandleError::EbpfMap)?;

    Ok(())
}

/// Log which program failed (to every configured log output, not just stderr) before
/// wrapping the error - the bare `EbpfAttach(...)` error doesn't name the program.
fn attach_failed(program_name: &str, e: aya::programs::ProgramError) -> PanhandleError {
    log::error!(
        "failed to load/attach eBPF program '{}': {}",
        program_name,
        e
    );
    PanhandleError::EbpfAttach(e)
}

/// Attach a (non-raw) tracepoint. Prefer this over `attach_raw_tracepoint` for syscall
/// tracepoints: the kernel only exposes raw tracepoints named `sys_enter`/`sys_exit`
/// (shared by every syscall, with no per-syscall raw tracepoint such as
/// `sys_enter_execve`), so `bpf_raw_tracepoint_open` always fails with ENOENT for a
/// per-syscall name.
pub fn attach_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    tracepoint_name: &str,
) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(|e| attach_failed(program_name, e))?;

    program.load().map_err(|e| attach_failed(program_name, e))?;
    program
        .attach(category, tracepoint_name)
        .map_err(|e| attach_failed(program_name, e))?;

    Ok(())
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
        .map_err(|e| attach_failed(program_name, e))?;

    program.load().map_err(|e| attach_failed(program_name, e))?;
    program
        .attach(tracepoint_name)
        .map_err(|e| attach_failed(program_name, e))?;

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
        .map_err(|e| attach_failed(program_name, e))?;

    program
        .load(tracepoint_name, btf)
        .map_err(|e| attach_failed(program_name, e))?;
    program
        .attach()
        .map_err(|e| attach_failed(program_name, e))?;

    Ok(())
}

/// Attach an fentry program (BTF trampoline fired on entry to `function_name`).
/// Prefer this over `attach_kprobe` for hot kernel functions: fentry/fexit attach via a
/// BTF trampoline instead of a breakpoint trap, at near-zero overhead per call (Linux 5.5+,
/// already implied by this crate's RingBuf-based event maps requiring 5.8+).
pub fn attach_fentry(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    function_name: &str,
    btf: &Btf,
) -> Result<()> {
    let program: &mut FEntry = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(|e| attach_failed(program_name, e))?;

    program
        .load(function_name, btf)
        .map_err(|e| attach_failed(program_name, e))?;
    program
        .attach()
        .map_err(|e| attach_failed(program_name, e))?;

    Ok(())
}

/// Attach an fexit program (BTF trampoline fired on return from `function_name`).
/// See `attach_fentry` for why this is preferred over `attach_kprobe`/kretprobe.
pub fn attach_fexit(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    function_name: &str,
    btf: &Btf,
) -> Result<()> {
    let program: &mut FExit = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(|e| attach_failed(program_name, e))?;

    program
        .load(function_name, btf)
        .map_err(|e| attach_failed(program_name, e))?;
    program
        .attach()
        .map_err(|e| attach_failed(program_name, e))?;

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
        .map_err(|e| attach_failed(program_name, e))?;

    program.load().map_err(|e| attach_failed(program_name, e))?;
    program
        .attach([attach_point], binary_path, UProbeScope::AllProcesses)
        .map_err(|e| attach_failed(program_name, e))?;

    Ok(())
}

/// Attach a kprobe/kretprobe. `function_name` is the kernel function being traced, which
/// isn't always the same as `program_name` (e.g. both a kprobe and a kretprobe on
/// `tcp_recvmsg` need distinct program names but attach to the same function).
pub fn attach_kprobe(ebpf: &mut aya::Ebpf, program_name: &str, function_name: &str) -> Result<()> {
    use aya::programs::KProbe;

    let program: &mut KProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(|e| attach_failed(program_name, e))?;

    program.load().map_err(|e| attach_failed(program_name, e))?;
    program
        .attach(function_name, 0)
        .map_err(|e| attach_failed(program_name, e))?;

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
        .map_err(|e| attach_failed(program_name, e))?;

    program
        .load(hook_name, btf)
        .map_err(|e| attach_failed(program_name, e))?;
    program
        .attach()
        .map_err(|e| attach_failed(program_name, e))?;

    Ok(())
}

/// Attach an LSM hook scoped to a single cgroup v2 directory instead of system-wide
/// (requires a kernel with LsmCgroup support, 6.0+). `cgroup_path` must be a cgroup v2
/// directory such as `/sys/fs/cgroup/myjob.slice`.
pub fn attach_lsm_cgroup_hook(
    ebpf: &mut aya::Ebpf,
    hook_name: &str,
    program_name: &str,
    btf: &Btf,
    cgroup_path: &std::path::Path,
) -> Result<()> {
    use aya::programs::LsmCgroup;

    let cgroup_file = std::fs::File::open(cgroup_path).map_err(|e| {
        PanhandleError::Config(format!(
            "Could not open cgroup path '{}': {}",
            cgroup_path.display(),
            e
        ))
    })?;

    let program: &mut LsmCgroup = ebpf
        .program_mut(program_name)
        .ok_or_else(|| PanhandleError::MissingProgram(program_name.to_string()))?
        .try_into()
        .map_err(|e| attach_failed(program_name, e))?;

    program
        .load(hook_name, btf)
        .map_err(|e| attach_failed(program_name, e))?;
    program
        .attach(cgroup_file)
        .map_err(|e| attach_failed(program_name, e))?;

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

/// Get a HashMap from the eBPF maps, taking ownership of it. Only safe to use once no
/// program still needs to be loaded/attached: `take_map` removes the map from the
/// `Ebpf` object's tracked maps, so a program loaded afterward can no longer resolve a
/// relocation against it ("fd N is not pointing to valid bpf_map" at load time). Needed
/// (over `get_hash_map_mut`) when the caller must move the map into a `'static` context,
/// e.g. a spawned task that outlives the function populating it.
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

/// Get a HashMap from the eBPF maps without removing it from the loaded object. Use this
/// (instead of `get_hash_map`) to populate a map's initial contents at load time, before
/// any program that relocates against it by name has been loaded/attached.
pub fn get_hash_map_mut<'a, K, V>(
    ebpf: &'a mut aya::Ebpf,
    map_name: &str,
) -> Result<aya::maps::HashMap<&'a mut aya::maps::MapData, K, V>>
where
    K: aya::Pod + Send + Sync + 'static,
    V: aya::Pod + Send + Sync + 'static,
{
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| PanhandleError::MissingMap(map_name.to_string()))?;

    aya::maps::HashMap::try_from(map).map_err(PanhandleError::EbpfMap)
}
