//! Functional option matrix: runs the real panhandle binary and checks every CLI option
//! and every config-file option, alone, in pairwise combinations, and with each output
//! channel - plus every input that must be rejected.
//!
//! Every check triggers the activity it looks for (a uniquely-marked exec, a shell or
//! `nobody` exec, an interactive bash/zsh line, a local TCP exchange) instead of waiting
//! for unrelated host activity, and every run asserts panhandle was still running when
//! it was stopped. Each setting is rendered three ways - CLI flags, a YAML config file,
//! and a JSON config file - and every case runs in each form that applies.
//!
//! Requires root, eBPF and kernel BTF, so the tests are `#[ignore]`d for plain
//! `cargo test`. `scripts/verify-functionality` builds and runs them; by hand:
//!
//!   cargo test -p panhandle --test functional_integration --no-run
//!   sudo target/debug/deps/functional_integration-<hash> --include-ignored --test-threads=1
//!
//! Enforcement of --syscalls blocking is checked by verify-functionality on hosts with
//! the bpf LSM active; here blocking is load-checked, scoped to an empty cgroup or a
//! comm nothing uses so it can never affect the host.

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_panhandle");
/// How long to let panhandle load and attach before triggering activity.
const ATTACH_WAIT: Duration = Duration::from_millis(1500);
/// Default length of a run that's expected to keep going.
const RUN: Duration = Duration::from_millis(4500);
const NOBODY: u32 = 65534;

// ---------------------------------------------------------------- settings

#[derive(Clone, Debug)]
enum Val {
    Num(i64),
    Str(String),
}

/// One setting, renderable as CLI arguments or a config-file entry. The config key is
/// the CLI flag with dashes turned into underscores.
#[derive(Clone, Debug)]
enum Opt {
    Flag(&'static str),
    Value(&'static str, Val),
    List(&'static str, Vec<Val>),
    File(PathBuf),
    Http(String),
    Syslog(String),
}

fn flag(key: &'static str) -> Opt {
    Opt::Flag(key)
}
fn num(key: &'static str, n: i64) -> Opt {
    Opt::Value(key, Val::Num(n))
}
fn text(key: &'static str, s: &str) -> Opt {
    Opt::Value(key, Val::Str(s.to_string()))
}
fn nums(key: &'static str, ns: &[i64]) -> Opt {
    Opt::List(key, ns.iter().map(|&n| Val::Num(n)).collect())
}
fn texts(key: &'static str, ss: &[&str]) -> Opt {
    Opt::List(key, ss.iter().map(|s| Val::Str(s.to_string())).collect())
}

/// Monitor root's own activity (the tests run as root; the default excluded range,
/// 0-999, would otherwise hide every exec the tests trigger).
fn include_root() -> Vec<Opt> {
    vec![num("exclude_min_uid", 60000), num("exclude_max_uid", 60000)]
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Cli,
    Yaml,
    Json,
}
const ALL_MODES: [Mode; 3] = [Mode::Cli, Mode::Yaml, Mode::Json];

fn cli_flag(key: &str) -> String {
    format!("--{}", key.replace('_', "-"))
}

fn val_cli(v: &Val) -> String {
    match v {
        Val::Num(n) => n.to_string(),
        Val::Str(s) => s.clone(),
    }
}

fn render_cli(opts: &[Opt]) -> Vec<String> {
    let mut args = Vec::new();
    let mut outputs = Vec::new();
    for opt in opts {
        match opt {
            Opt::Flag(k) => args.push(cli_flag(k)),
            Opt::Value(k, v) => args.extend([cli_flag(k), val_cli(v)]),
            Opt::List(k, vs) => args.extend([
                cli_flag(k),
                vs.iter().map(val_cli).collect::<Vec<_>>().join(","),
            ]),
            Opt::File(p) => outputs.extend(["--file".into(), p.display().to_string()]),
            Opt::Http(u) => outputs.extend(["--http".into(), u.clone()]),
            Opt::Syslog(a) => outputs.extend(["--syslog".into(), a.clone()]),
        }
    }
    if !outputs.is_empty() {
        args.push("output".into());
        args.extend(outputs);
    }
    args
}

fn val_json(v: &Val) -> serde_json::Value {
    match v {
        Val::Num(n) => serde_json::json!(n),
        Val::Str(s) => serde_json::json!(s),
    }
}

fn render_json(opts: &[Opt]) -> String {
    let mut map = serde_json::Map::new();
    let mut outputs = Vec::new();
    for opt in opts {
        match opt {
            Opt::Flag(k) => {
                map.insert(k.to_string(), serde_json::json!(true));
            }
            Opt::Value(k, v) => {
                map.insert(k.to_string(), val_json(v));
            }
            Opt::List(k, vs) => {
                map.insert(k.to_string(), vs.iter().map(val_json).collect());
            }
            Opt::File(p) => outputs.push(serde_json::json!({ "file": p })),
            Opt::Http(u) => outputs.push(serde_json::json!({ "http": u })),
            Opt::Syslog(a) => outputs.push(serde_json::json!({ "syslog": a })),
        }
    }
    if !outputs.is_empty() {
        map.insert("output".into(), outputs.into());
    }
    serde_json::Value::Object(map).to_string()
}

// Block-style YAML with flow lists; strings are double-quoted (JSON string syntax is a
// valid YAML double-quoted scalar).
fn render_yaml(opts: &[Opt]) -> String {
    let q = |s: &str| serde_json::to_string(s).unwrap();
    let scalar = |v: &Val| match v {
        Val::Num(n) => n.to_string(),
        Val::Str(s) => q(s),
    };
    let mut out = String::new();
    let mut outputs = Vec::new();
    for opt in opts {
        match opt {
            Opt::Flag(k) => out += &format!("{k}: true\n"),
            Opt::Value(k, v) => out += &format!("{k}: {}\n", scalar(v)),
            Opt::List(k, vs) => {
                let items: Vec<String> = vs.iter().map(scalar).collect();
                out += &format!("{k}: [{}]\n", items.join(", "));
            }
            Opt::File(p) => outputs.push(format!("  - file: {}", q(&p.display().to_string()))),
            Opt::Http(u) => outputs.push(format!("  - http: {}", q(u))),
            Opt::Syslog(a) => outputs.push(format!("  - syslog: {}", q(a))),
        }
    }
    if !outputs.is_empty() {
        out += "output:\n";
        out += &outputs.join("\n");
        out += "\n";
    }
    out
}

// ---------------------------------------------------------------- running

struct Run {
    out: String,
    /// Exit code if panhandle exited on its own before being stopped.
    exited: Option<i32>,
}

impl Run {
    fn has(&self, s: &str) -> bool {
        self.out.contains(s)
    }
}

/// Run panhandle with `opts` rendered in `mode`, call `trigger` once it has had time to
/// attach, then stop it with SIGINT once `total` has elapsed (or as soon as it exits).
fn run_with(
    opts: &[Opt],
    mode: Mode,
    extra_args: &[&str],
    trigger: impl FnOnce(),
    total: Duration,
) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(BIN);
    match mode {
        Mode::Cli => {
            cmd.args(render_cli(opts));
        }
        Mode::Yaml | Mode::Json => {
            let (name, body) = if mode == Mode::Yaml {
                ("panhandle.yaml", render_yaml(opts))
            } else {
                ("panhandle.json", render_json(opts))
            };
            let path = dir.path().join(name);
            fs::write(&path, body).unwrap();
            cmd.arg("--config").arg(&path);
        }
    }
    cmd.args(extra_args);
    spawn_and_collect(cmd, trigger, total)
}

fn run(opts: &[Opt], mode: Mode, trigger: impl FnOnce(), total: Duration) -> Run {
    run_with(opts, mode, &[], trigger, total)
}

fn spawn_and_collect(mut cmd: Command, trigger: impl FnOnce(), total: Duration) -> Run {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn panhandle");
    // drain both pipes concurrently so a chatty monitor can't block on a full pipe
    let drain = |mut r: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = r.read_to_end(&mut buf);
            buf
        })
    };
    let out_t = drain(Box::new(child.stdout.take().unwrap()));
    let err_t = drain(Box::new(child.stderr.take().unwrap()));

    let start = Instant::now();
    let exited_by = |child: &mut std::process::Child, until: Duration| loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status.code().unwrap_or(-1));
        }
        if start.elapsed() >= until {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let mut exited = exited_by(&mut child, ATTACH_WAIT.min(total));
    if exited.is_none() {
        trigger();
        exited = exited_by(&mut child, total);
    }
    if exited.is_none() {
        let _ = Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(3);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    let mut out = String::from_utf8_lossy(&out_t.join().unwrap()).to_string();
    out += &String::from_utf8_lossy(&err_t.join().unwrap());
    Run { out, exited }
}

fn prerequisites() {
    assert_eq!(
        uzers::get_current_uid(),
        0,
        "run the test binary as root (see the module docs)"
    );
    assert!(
        Path::new("/sys/kernel/btf/vmlinux").exists(),
        "kernel BTF (/sys/kernel/btf/vmlinux) is required"
    );
}

static MARKER_SEQ: AtomicU32 = AtomicU32::new(0);
fn marker(tag: &str) -> String {
    format!("pnhmk{}{}", tag, MARKER_SEQ.fetch_add(1, Ordering::Relaxed))
}

// ---------------------------------------------------------------- triggers

fn exec_echo(marker: &str) {
    let _ = Command::new("/bin/echo")
        .arg(marker)
        .stdout(Stdio::null())
        .status();
}

fn exec_echo_as(uid: u32, marker: &str) {
    let _ = Command::new("/bin/echo")
        .arg(marker)
        .uid(uid)
        .gid(uid)
        .stdout(Stdio::null())
        .status();
}

fn exec_true(marker: &str) {
    let _ = Command::new("/bin/true").arg(marker).status();
}

/// An exec made *by a shell* (comm sh), for --shells.
fn shell_exec_echo(marker: &str) {
    let _ = Command::new("/bin/sh")
        .args(["-c", &format!("/bin/echo {marker}; :")])
        .stdout(Stdio::null())
        .status();
}

/// Type a line into an interactive shell on a pty (readline for bash, zle for zsh).
fn interactive_line(shell: &str, marker: &str) {
    let shell_cmd = match shell {
        "bash" => "bash --norc --noprofile -i",
        _ => "zsh -f -i",
    };
    let mut child = Command::new("script")
        .args(["-qec", shell_cmd, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn script");
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(format!("echo {marker}\nexit\n").as_bytes());
    drop(stdin);
    let _ = child.wait();
}

/// A few local TCP round trips with a short delay before each reply, so the test
/// process has socket traffic (--socket) and real network waits (--bound).
fn tcp_exchange() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            let mut buf = [0u8; 64];
            for _ in 0..3 {
                if conn.read(&mut buf).unwrap_or(0) == 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
                let _ = conn.write_all(b"pong");
            }
        }
    });
    if let Ok(mut conn) = TcpStream::connect(addr) {
        let mut buf = [0u8; 64];
        for _ in 0..3 {
            let _ = conn.write_all(b"ping");
            let _ = conn.read(&mut buf);
        }
    }
    let _ = server.join();
}

// ---------------------------------------------------------------- output checks

/// Whether any line reports `ty` in prose ("Type: cpu,") or JSON form.
fn has_type(run: &Run, ty: &str) -> bool {
    run.out.lines().any(|line| {
        line.contains(&format!("Type: {ty},"))
            || json_of(line).is_some_and(|v| v.get("Type").and_then(|t| t.as_str()) == Some(ty))
    })
}

/// The JSON object on a log line (output lines carry a log prefix before the `{`).
fn json_of(line: &str) -> Option<serde_json::Value> {
    let start = line.find('{')?;
    let value: serde_json::Value = serde_json::from_str(&line[start..]).ok()?;
    value.is_object().then_some(value)
}

/// Lines reporting `ty`, prose or JSON.
fn type_lines<'a>(run: &'a Run, ty: &str) -> Vec<&'a str> {
    run.out
        .lines()
        .filter(|line| {
            line.contains(&format!("Type: {ty},"))
                || json_of(line).is_some_and(|v| v.get("Type").and_then(|t| t.as_str()) == Some(ty))
        })
        .collect()
}

/// PID reported on a monitor line, prose or JSON.
fn line_pid(line: &str) -> Option<i64> {
    if let Some(v) = json_of(line) {
        return v.get("PID").and_then(|p| p.as_i64());
    }
    let rest = &line[line.find("PID: ")? + 5..];
    rest.split(',').next()?.trim().parse().ok()
}

fn alive(run: &Run) -> Result<(), String> {
    match run.exited {
        None if !run.has("panicked") => Ok(()),
        None => Err("panicked".into()),
        Some(code) => Err(format!("exited early with code {code}")),
    }
}

// ---------------------------------------------------------------- monitors

/// A monitor: the setting that enables it, the activity that exercises it, and the
/// check that it reported that activity.
struct Monitor {
    name: &'static str,
    opts: fn() -> Vec<Opt>,
    trigger: fn(&str),
    check: fn(&Run, &str) -> Result<(), String>,
}

fn expect(cond: bool, what: impl Into<String>) -> Result<(), String> {
    if cond { Ok(()) } else { Err(what.into()) }
}

fn monitors() -> Vec<Monitor> {
    vec![
        Monitor {
            name: "syscall_execve",
            opts: || vec![flag("syscall_execve")],
            trigger: exec_echo,
            check: |r, m| expect(r.has(m), format!("no execve event for marker {m}")),
        },
        Monitor {
            name: "bash",
            opts: || vec![flag("bash")],
            trigger: |m| interactive_line("bash", m),
            check: |r, m| expect(r.has(&format!("echo {m}")), "no bash readline event"),
        },
        Monitor {
            name: "zsh",
            opts: || vec![flag("zsh")],
            trigger: |m| interactive_line("zsh", m),
            check: |r, m| expect(r.has(&format!("echo {m}")), "no zsh zle event"),
        },
        Monitor {
            name: "cpu",
            opts: || vec![flag("cpu")],
            trigger: |_| {},
            check: |r, _| expect(has_type(r, "cpu"), "no cpu report"),
        },
        Monitor {
            name: "memory",
            opts: || vec![flag("memory")],
            trigger: |_| {},
            check: |r, _| expect(has_type(r, "mem"), "no memory report"),
        },
        Monitor {
            name: "io",
            opts: || vec![flag("io")],
            trigger: |_| {},
            check: |r, _| expect(has_type(r, "io"), "no io report"),
        },
        Monitor {
            name: "memory_faults",
            opts: || vec![num("memory_faults", 0)],
            trigger: |_| {},
            check: |r, _| expect(has_type(r, "fault"), "no memory-faults report"),
        },
        Monitor {
            name: "socket",
            opts: || vec![flag("socket")],
            trigger: |_| tcp_exchange(),
            check: |r, _| expect(has_type(r, "sock"), "no socket report"),
        },
        Monitor {
            name: "bound",
            opts: || vec![flag("bound")],
            trigger: |_| tcp_exchange(),
            check: |r, _| expect(has_type(r, "bound"), "no bound report"),
        },
        Monitor {
            // no GPU is assumed: only checks that it starts and keeps running
            name: "gpu",
            opts: || vec![flag("gpu")],
            trigger: |_| {},
            check: |_, _| Ok(()),
        },
    ]
}

/// Options every monitor run gets: root's activity included, 1-second polling.
fn base_opts() -> Vec<Opt> {
    let mut opts = include_root();
    opts.push(num("poll", 1));
    opts
}

// ---------------------------------------------------------------- failure collection

#[derive(Default)]
struct Failures(Vec<String>);

impl Failures {
    fn check(&mut self, case: &str, result: Result<(), String>, run: Option<&Run>) {
        match result {
            Ok(()) => println!("PASS {case}"),
            Err(why) => {
                println!("FAIL {case}: {why}");
                let tail = run
                    .map(|r| {
                        let lines: Vec<&str> = r.out.lines().collect();
                        lines[lines.len().saturating_sub(8)..].join("\n    ")
                    })
                    .unwrap_or_default();
                self.0.push(format!("{case}: {why}\n    {tail}"));
            }
        }
    }

    fn assert_none(self) {
        assert!(
            self.0.is_empty(),
            "{} case(s) failed:\n{}",
            self.0.len(),
            self.0.join("\n")
        );
    }
}

fn run_monitor_case(f: &mut Failures, case: &str, opts: &[Opt], mode: Mode, mons: &[&Monitor]) {
    let markers: Vec<String> = mons.iter().map(|m| marker(m.name)).collect();
    let r = run(
        opts,
        mode,
        || {
            for (m, mk) in mons.iter().zip(&markers) {
                (m.trigger)(mk);
            }
        },
        RUN,
    );
    let result = alive(&r).and_then(|()| {
        mons.iter()
            .zip(&markers)
            .try_for_each(|(m, mk)| (m.check)(&r, mk).map_err(|e| format!("[{}] {e}", m.name)))
    });
    f.check(case, result, Some(&r));
}

// ================================================================= tests

/// Every monitor on its own, from the CLI and from YAML and JSON config files.
#[test]
#[ignore]
fn matrix_each_monitor_every_mode() {
    prerequisites();
    let mut f = Failures::default();
    for m in &monitors() {
        for mode in ALL_MODES {
            let mut opts = base_opts();
            opts.extend((m.opts)());
            run_monitor_case(&mut f, &format!("{} [{mode:?}]", m.name), &opts, mode, &[m]);
        }
    }
    f.assert_none();
}

/// The default execve monitor (no monitor flags at all).
#[test]
#[ignore]
fn matrix_default_execve_monitor() {
    prerequisites();
    let mut f = Failures::default();
    for mode in ALL_MODES {
        let mk = marker("default");
        let r = run(&include_root(), mode, || exec_echo(&mk), RUN);
        let result = alive(&r).and_then(|()| expect(r.has(&mk), "no execve event"));
        f.check(&format!("default execve [{mode:?}]"), result, Some(&r));
    }
    f.assert_none();
}

/// Every pair of monitors at once: both must still report.
#[test]
#[ignore]
fn matrix_monitor_pairs() {
    prerequisites();
    let mut f = Failures::default();
    let mons = monitors();
    for (i, a) in mons.iter().enumerate() {
        for b in &mons[i + 1..] {
            let mut opts = base_opts();
            opts.extend((a.opts)());
            opts.extend((b.opts)());
            run_monitor_case(
                &mut f,
                &format!("{} + {}", a.name, b.name),
                &opts,
                Mode::Cli,
                &[a, b],
            );
        }
    }
    // and everything at once
    let mut opts = base_opts();
    let all: Vec<&Monitor> = mons.iter().collect();
    for m in &all {
        opts.extend((m.opts)());
    }
    run_monitor_case(&mut f, "all monitors at once", &opts, Mode::Cli, &all);
    f.assert_none();
}

/// Every monitor combined with each output modifier (--json, --verbose, --debug).
#[test]
#[ignore]
fn matrix_monitor_modifiers() {
    prerequisites();
    let mut f = Failures::default();
    for m in &monitors() {
        for modifier in ["json", "verbose", "debug"] {
            let mut opts = base_opts();
            opts.extend((m.opts)());
            opts.push(flag(modifier));
            run_monitor_case(
                &mut f,
                &format!("{} + --{modifier}", m.name),
                &opts,
                Mode::Cli,
                &[m],
            );
        }
    }
    f.assert_none();
}

/// What each output-shaping option actually changes.
#[test]
#[ignore]
fn matrix_output_modifiers() {
    prerequisites();
    let mut f = Failures::default();
    for mode in ALL_MODES {
        // --json: the event line is a JSON object
        let mk = marker("json");
        let mut opts = include_root();
        opts.push(flag("json"));
        let r = run(&opts, mode, || exec_echo(&mk), RUN);
        let result = alive(&r).and_then(|()| {
            let line = r.out.lines().find(|l| l.contains(&mk)).ok_or("no event")?;
            let v = json_of(line).ok_or_else(|| format!("event line isn't JSON: {line}"))?;
            expect(v.get("filename").is_some(), "JSON event has no filename")
        });
        f.check(
            &format!("--json execve event is JSON [{mode:?}]"),
            result,
            Some(&r),
        );

        // --json resource report
        let opts = vec![
            flag("cpu"),
            num("poll", 1),
            nums("pid_list", &[1]),
            flag("json"),
        ];
        let r = run(&opts, mode, || {}, RUN);
        let result = alive(&r).and_then(|()| {
            let lines = type_lines(&r, "cpu");
            expect(!lines.is_empty(), "no cpu report")?;
            expect(
                lines.iter().all(|l| json_of(l).is_some()),
                "a cpu report line isn't JSON",
            )
        });
        f.check(
            &format!("--json cpu report is JSON [{mode:?}]"),
            result,
            Some(&r),
        );

        // --verbose adds parent/owner fields
        let opts = vec![
            flag("cpu"),
            num("poll", 1),
            nums("pid_list", &[1]),
            flag("verbose"),
        ];
        let r = run(&opts, mode, || {}, RUN);
        let result = alive(&r).and_then(|()| expect(r.has("Parent PID"), "no Parent PID field"));
        f.check(
            &format!("--verbose adds parent fields [{mode:?}]"),
            result,
            Some(&r),
        );

        // --debug prints debug diagnostics
        let mut opts = include_root();
        opts.push(flag("debug"));
        let r = run(&opts, mode, || {}, RUN);
        let result =
            alive(&r).and_then(|()| expect(r.has("monitoring for events"), "no debug output"));
        f.check(
            &format!("--debug prints diagnostics [{mode:?}]"),
            result,
            Some(&r),
        );

        // --quiet: no terminal output for events
        let mk = marker("quiet");
        let mut opts = include_root();
        opts.push(flag("quiet"));
        let r = run(&opts, mode, || exec_echo(&mk), RUN);
        let result = alive(&r).and_then(|()| expect(!r.has(&mk), "event printed despite --quiet"));
        f.check(
            &format!("--quiet suppresses terminal output [{mode:?}]"),
            result,
            Some(&r),
        );
    }
    f.assert_none();
}

/// The execve filters: --shells, --executables, --include-uid, the exclude range.
#[test]
#[ignore]
fn matrix_execve_filters() {
    prerequisites();
    let mut f = Failures::default();
    for mode in ALL_MODES {
        // --shells: execs made by a shell are reported, others aren't
        let (sh, other) = (marker("sh"), marker("nosh"));
        let mut opts = include_root();
        opts.push(flag("shells"));
        let r = run(
            &opts,
            mode,
            || {
                shell_exec_echo(&sh);
                exec_echo(&other);
            },
            RUN,
        );
        let result = alive(&r)
            .and_then(|()| expect(r.has(&sh), "exec by a shell not reported"))
            .and_then(|()| expect(!r.has(&other), "exec by a non-shell reported"));
        f.check(&format!("--shells [{mode:?}]"), result, Some(&r));

        // --executables: only the listed executable is reported
        let (hit, miss) = (marker("exe"), marker("noexe"));
        let mut opts = include_root();
        opts.push(texts("executables", &["/bin/echo"]));
        let r = run(
            &opts,
            mode,
            || {
                exec_echo(&hit);
                exec_true(&miss);
            },
            RUN,
        );
        let result = alive(&r)
            .and_then(|()| expect(r.has(&hit), "listed executable not reported"))
            .and_then(|()| expect(!r.has(&miss), "unlisted executable reported"));
        f.check(&format!("--executables [{mode:?}]"), result, Some(&r));

        // --include-uid (numeric form; config files also accept strings, tested below)
        let (nob, root) = (marker("nobody"), marker("root"));
        let mut opts = include_root();
        opts.push(nums("include_uid", &[NOBODY as i64]));
        let r = run(
            &opts,
            mode,
            || {
                exec_echo_as(NOBODY, &nob);
                exec_echo(&root);
            },
            RUN,
        );
        let result = alive(&r)
            .and_then(|()| expect(r.has(&nob), "included uid not reported"))
            .and_then(|()| expect(!r.has(&root), "non-included uid reported"));
        f.check(&format!("--include-uid [{mode:?}]"), result, Some(&r));

        // exclude range covering nobody but not root
        let (nob, root) = (marker("exnobody"), marker("exroot"));
        let opts = vec![num("exclude_min_uid", 60000), num("exclude_max_uid", 65535)];
        let r = run(
            &opts,
            mode,
            || {
                exec_echo_as(NOBODY, &nob);
                exec_echo(&root);
            },
            RUN,
        );
        let result = alive(&r)
            .and_then(|()| expect(r.has(&root), "uid outside the excluded range not reported"))
            .and_then(|()| expect(!r.has(&nob), "uid inside the excluded range reported"));
        f.check(
            &format!("--exclude-min/max-uid [{mode:?}]"),
            result,
            Some(&r),
        );

        // default exclude range (0-999) hides root
        let mk = marker("defexcl");
        let r = run(&[], mode, || exec_echo(&mk), RUN);
        let result = alive(&r)
            .and_then(|()| expect(!r.has(&mk), "root reported despite default exclude range"));
        f.check(
            &format!("default exclude range hides root [{mode:?}]"),
            result,
            Some(&r),
        );
    }
    // config files also accept include_uid as strings
    for mode in [Mode::Yaml, Mode::Json] {
        let (nob, root) = (marker("snobody"), marker("sroot"));
        let mut opts = include_root();
        opts.push(texts("include_uid", &["65534"]));
        let r = run(
            &opts,
            mode,
            || {
                exec_echo_as(NOBODY, &nob);
                exec_echo(&root);
            },
            RUN,
        );
        let result = alive(&r)
            .and_then(|()| expect(r.has(&nob), "included uid (string form) not reported"))
            .and_then(|()| expect(!r.has(&root), "non-included uid reported"));
        f.check(
            &format!("include_uid as strings [{mode:?}]"),
            result,
            Some(&r),
        );
    }
    f.assert_none();
}

/// --pid-list restricts every resource monitor to the listed PIDs.
#[test]
#[ignore]
fn matrix_pid_list_filters_each_resource_monitor() {
    prerequisites();
    let mut f = Failures::default();
    let me = std::process::id() as i64;
    for (name, opt, ty, pid, trig) in [
        ("cpu", flag("cpu"), "cpu", 1, None),
        ("memory", flag("memory"), "mem", 1, None),
        ("io", flag("io"), "io", 1, None),
        ("memory_faults", num("memory_faults", 0), "fault", 1, None),
        ("bound", flag("bound"), "bound", 1, None),
        (
            "socket",
            flag("socket"),
            "sock",
            me,
            Some(tcp_exchange as fn()),
        ),
    ] {
        for mode in ALL_MODES {
            let opts = vec![opt.clone(), num("poll", 1), nums("pid_list", &[pid])];
            let r = run(
                &opts,
                mode,
                || {
                    if let Some(t) = trig {
                        t()
                    }
                },
                RUN,
            );
            let result = alive(&r).and_then(|()| {
                let lines = type_lines(&r, ty);
                expect(!lines.is_empty(), format!("no {ty} report for pid {pid}"))?;
                // --cpu also prints a PID-less system-wide summary line every poll
                let outside = lines.iter().find(|l| match line_pid(l) {
                    Some(p) => p != pid,
                    None => ty != "cpu",
                });
                match outside {
                    Some(l) => Err(format!("reported a pid outside --pid-list: {l}")),
                    None => Ok(()),
                }
            });
            f.check(
                &format!("--pid-list with {name} [{mode:?}]"),
                result,
                Some(&r),
            );
        }
    }
    f.assert_none();
}

/// --poll sets the report cadence.
#[test]
#[ignore]
fn matrix_poll_cadence() {
    prerequisites();
    let mut f = Failures::default();
    for mode in ALL_MODES {
        // one cpu line per poll for pid 1: ~6.5s at poll 2 gives 3-4 reports
        let opts = vec![flag("cpu"), num("poll", 2), nums("pid_list", &[1])];
        let r = run(&opts, mode, || {}, Duration::from_millis(6500));
        // count pid 1's lines only (each poll also prints a system-wide summary line)
        let n = type_lines(&r, "cpu")
            .iter()
            .filter(|l| line_pid(l) == Some(1))
            .count();
        let result = alive(&r).and_then(|()| {
            expect(
                (2..=5).contains(&n),
                format!("{n} reports in 6.5s at --poll 2"),
            )
        });
        f.check(&format!("--poll 2 cadence [{mode:?}]"), result, Some(&r));
    }
    f.assert_none();
}

/// A tiny HTTP server that records request bodies and answers 200.
fn http_sink() -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/events", listener.local_addr().unwrap());
    let got = Arc::new(Mutex::new(String::new()));
    let sink = got.clone();
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let sink = sink.clone();
            thread::spawn(move || {
                let mut conn = conn;
                conn.set_read_timeout(Some(Duration::from_millis(500))).ok();
                let mut buf = vec![0u8; 1 << 16];
                if let Ok(n) = conn.read(&mut buf) {
                    sink.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n]));
                }
                let _ = conn.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    (url, got)
}

fn udp_syslog_sink() -> (String, Arc<Mutex<String>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = format!("{}/udp", sock.local_addr().unwrap());
    let got = Arc::new(Mutex::new(String::new()));
    let sink = got.clone();
    thread::spawn(move || {
        let mut buf = vec![0u8; 1 << 16];
        while let Ok(n) = sock.recv(&mut buf) {
            sink.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
    (addr, got)
}

fn tcp_syslog_sink() -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("{}/tcp", listener.local_addr().unwrap());
    let got = Arc::new(Mutex::new(String::new()));
    let sink = got.clone();
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let sink = sink.clone();
            thread::spawn(move || {
                let mut conn = conn;
                let mut buf = vec![0u8; 1 << 16];
                while let Ok(n) = conn.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    sink.lock()
                        .unwrap()
                        .push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            });
        }
    });
    (addr, got)
}

/// Reads back everything an output channel has received so far.
type Received = Box<dyn Fn() -> String>;

/// Each output channel, alone and all together, receives events.
#[test]
#[ignore]
fn matrix_output_channels() {
    prerequisites();
    let mut f = Failures::default();
    for mode in ALL_MODES {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("events.log");
        let (url, http_got) = http_sink();
        let (udp, udp_got) = udp_syslog_sink();
        let (tcp, tcp_got) = tcp_syslog_sink();

        let channels: Vec<(&str, Opt, Received)> = vec![
            (
                "file",
                Opt::File(file.clone()),
                Box::new({
                    let file = file.clone();
                    move || fs::read_to_string(&file).unwrap_or_default()
                }),
            ),
            (
                "http",
                Opt::Http(url.clone()),
                Box::new({
                    let g = http_got.clone();
                    move || g.lock().unwrap().clone()
                }),
            ),
            (
                "syslog udp",
                Opt::Syslog(udp.clone()),
                Box::new({
                    let g = udp_got.clone();
                    move || g.lock().unwrap().clone()
                }),
            ),
            (
                "syslog tcp",
                Opt::Syslog(tcp.clone()),
                Box::new({
                    let g = tcp_got.clone();
                    move || g.lock().unwrap().clone()
                }),
            ),
        ];

        for (name, out_opt, received) in &channels {
            let mk = marker("out");
            let mut opts = include_root();
            opts.push(out_opt.clone());
            let r = run(&opts, mode, || exec_echo(&mk), RUN);
            let result = alive(&r).and_then(|()| {
                expect(
                    received().contains(&mk),
                    format!("{name} didn't receive the event"),
                )
            });
            f.check(&format!("output {name} [{mode:?}]"), result, Some(&r));
        }

        // file + http + syslog (udp) together, in JSON
        let mk = marker("allout");
        let mut opts = include_root();
        opts.extend([
            flag("json"),
            Opt::File(file.clone()),
            Opt::Http(url.clone()),
            Opt::Syslog(udp.clone()),
        ]);
        let r = run(&opts, mode, || exec_echo(&mk), RUN);
        let result = alive(&r)
            .and_then(|()| expect(channels[0].2().contains(&mk), "file missed the event"))
            .and_then(|()| expect(channels[1].2().contains(&mk), "http missed the event"))
            .and_then(|()| expect(channels[2].2().contains(&mk), "syslog missed the event"));
        f.check(
            &format!("output file+http+syslog together [{mode:?}]"),
            result,
            Some(&r),
        );
    }
    f.assert_none();
}

/// A config value is overridden by the same option on the CLI.
#[test]
#[ignore]
fn matrix_cli_overrides_config() {
    prerequisites();
    let mut f = Failures::default();
    for mode in [Mode::Yaml, Mode::Json] {
        let config = vec![flag("cpu"), num("poll", 5), nums("pid_list", &[1])];
        let r = run_with(&config, mode, &["--poll", "1", "--debug"], || {}, RUN);
        let result = alive(&r)
            .and_then(|()| {
                expect(
                    r.has("poll=cli"),
                    "merge provenance doesn't show poll from the CLI",
                )
            })
            .and_then(|()| {
                let n = type_lines(&r, "cpu")
                    .iter()
                    .filter(|l| line_pid(l) == Some(1))
                    .count();
                expect(
                    n >= 2,
                    format!("only {n} cpu reports for pid 1: --poll 1 from the CLI didn't apply"),
                )
            });
        f.check(
            &format!("CLI --poll overrides config poll [{mode:?}]"),
            result,
            Some(&r),
        );
    }
    f.assert_none();
}

/// An empty cgroup to scope blocking to, so these load checks can't block anything.
struct ScratchCgroup(PathBuf);
impl ScratchCgroup {
    fn new() -> Self {
        let path = PathBuf::from(format!(
            "/sys/fs/cgroup/panhandle_matrix_{}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create scratch cgroup");
        Self(path)
    }
}
impl Drop for ScratchCgroup {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

/// Every --syscalls value and combination, with each list mode, system-wide and
/// cgroup-scoped, must load and run. System-wide runs deny a comm nothing uses; allow
/// lists (which block everything not listed) only ever run scoped to an empty cgroup.
#[test]
#[ignore]
fn matrix_blocking_loads() {
    prerequisites();
    let mut f = Failures::default();
    let cg = ScratchCgroup::new();
    let cg_path = cg.0.display().to_string();
    let syscall_sets: [&[&str]; 6] = [
        &["open"],
        &["openat"],
        &["creat"],
        &["execve"],
        &["open", "openat", "creat"],
        &["open", "openat", "creat", "execve"],
    ];
    for syscalls in syscall_sets {
        for mode in ALL_MODES {
            let variants: Vec<(&str, Vec<Opt>)> = vec![
                ("deny", vec![texts("comm_deny", &["pnh_nobody_cmd"])]),
                (
                    "deny + block_paths",
                    vec![
                        texts("comm_deny", &["pnh_nobody_cmd"]),
                        texts("block_paths", &["/etc/shadow", "/etc/gshadow"]),
                    ],
                ),
                (
                    "deny, cgroup",
                    vec![
                        texts("comm_deny", &["pnh_nobody_cmd"]),
                        text("cgroup", &cg_path),
                    ],
                ),
                (
                    "allow, cgroup",
                    vec![
                        texts("comm_allow", &["pnh_nobody_cmd"]),
                        text("cgroup", &cg_path),
                    ],
                ),
                ("no list, cgroup", vec![text("cgroup", &cg_path)]),
            ];
            for (variant, extra) in variants {
                let mut opts = vec![texts("syscalls", syscalls), flag("debug")];
                opts.extend(extra);
                let r = run(&opts, mode, || {}, Duration::from_millis(3500));
                let result = alive(&r)
                    .and_then(|()| {
                        expect(
                            r.has("monitoring for events"),
                            "never reached the event loop",
                        )
                    })
                    .and_then(|()| {
                        expect(
                            !r.has("failed to load/attach"),
                            "an LSM program failed to load",
                        )
                    });
                f.check(
                    &format!("--syscalls {} ({variant}) [{mode:?}]", syscalls.join(",")),
                    result,
                    Some(&r),
                );
            }
        }
    }
    f.assert_none();
}

/// Inputs that must be rejected at startup, from the CLI and from config files, each
/// with its specific error.
#[test]
#[ignore]
fn matrix_rejected_inputs() {
    prerequisites();
    let mut f = Failures::default();
    let long_comm = "abcdefghijklmnop"; // 16 bytes
    let long_path = format!("/{}", "a".repeat(256));
    let many = |prefix: &str, n: usize| -> Vec<String> {
        (1..=n).map(|i| format!("{prefix}{i}")).collect()
    };
    let exes = many("/bin/x", 21);
    let paths = many("/p", 65);
    let comms = many("c", 65);
    let refs = |v: &[String]| -> Vec<String> { v.to_vec() };

    // (case, opts, any of these messages)
    let cases: Vec<(&str, Vec<Opt>, Vec<&str>)> = vec![
        (
            "both comm lists",
            vec![
                texts("syscalls", &["execve"]),
                texts("comm_deny", &["a"]),
                texts("comm_allow", &["b"]),
            ],
            vec!["Allow and deny list both provided"],
        ),
        (
            "unsupported syscall",
            vec![texts("syscalls", &["exec"]), texts("comm_deny", &["a"])],
            vec!["Unsupported --syscalls value 'exec'"],
        ),
        (
            "poll 0",
            vec![num("poll", 0)],
            vec!["0 is not in 1..", "--poll must be at least 1"],
        ),
        (
            "inverted uid range",
            vec![num("exclude_min_uid", 1000), num("exclude_max_uid", 5)],
            vec!["must not be greater than"],
        ),
        (
            "min uid above default max",
            vec![num("exclude_min_uid", 1000)],
            vec!["must not be greater than --exclude-max-uid (999)"],
        ),
        (
            "non-numeric include_uid",
            vec![texts("include_uid", &["abc"])],
            vec!["Invalid --include-uid value 'abc'"],
        ),
        (
            "negative include_uid",
            vec![nums("include_uid", &[-5])],
            vec!["Invalid --include-uid value '-5'", "unexpected argument"],
        ),
        (
            "21 executables",
            vec![Opt::List(
                "executables",
                refs(&exes).into_iter().map(Val::Str).collect(),
            )],
            vec!["exceeds the maximum of 20"],
        ),
        (
            "11 include_uids",
            vec![nums("include_uid", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])],
            vec!["exceeds the maximum of 10"],
        ),
        (
            "16-byte comm",
            vec![
                texts("syscalls", &["execve"]),
                texts("comm_deny", &[long_comm]),
            ],
            vec!["exceeds maximum length of 15"],
        ),
        (
            "256-byte path",
            vec![
                texts("syscalls", &["open"]),
                texts("comm_deny", &["a"]),
                texts("block_paths", &[&long_path]),
            ],
            vec!["exceeds maximum length of 255"],
        ),
        (
            "65 block_paths",
            vec![
                texts("syscalls", &["open"]),
                texts("comm_deny", &["a"]),
                Opt::List(
                    "block_paths",
                    refs(&paths).into_iter().map(Val::Str).collect(),
                ),
            ],
            vec!["exceeds the maximum of 64"],
        ),
        (
            "65 comms",
            vec![
                texts("syscalls", &["open"]),
                Opt::List(
                    "comm_deny",
                    refs(&comms).into_iter().map(Val::Str).collect(),
                ),
            ],
            vec!["exceeds the maximum of 64"],
        ),
        (
            "negative pid",
            vec![nums("pid_list", &[-1])],
            vec!["unexpected argument", "invalid value", "Invalid"],
        ),
        (
            "non-numeric memory_faults",
            vec![text("memory_faults", "abc")],
            vec!["invalid", "Invalid"],
        ),
        (
            "invalid http url",
            vec![flag("cpu"), Opt::Http("notaurl".into())],
            vec!["Invalid URL 'notaurl'"],
        ),
        (
            "unreachable syslog tcp port",
            vec![flag("cpu"), Opt::Syslog("127.0.0.1:1/tcp".into())],
            vec!["not reachable"],
        ),
        (
            "malformed syslog address",
            vec![flag("cpu"), Opt::Syslog("bogus_format".into())],
            vec!["Invalid syslog argument"],
        ),
        (
            "missing cgroup path",
            vec![
                texts("syscalls", &["execve"]),
                texts("comm_deny", &["a"]),
                text("cgroup", "/sys/fs/cgroup/pnh_does_not_exist"),
            ],
            vec!["Could not open cgroup path"],
        ),
    ];
    for (case, opts, messages) in &cases {
        for mode in ALL_MODES {
            let r = run(opts, mode, || {}, Duration::from_secs(5));
            let result = match r.exited {
                Some(0) => Err("exited 0".to_string()),
                None => Err("wasn't rejected (still running)".to_string()),
                Some(_) => expect(
                    messages.iter().any(|m| r.has(m)),
                    format!("rejected without the expected message (any of {messages:?})"),
                ),
            };
            f.check(&format!("rejects {case} [{mode:?}]"), result, Some(&r));
        }
    }

    // config-file-only failures
    let dir = tempfile::tempdir().unwrap();
    let file_cases: Vec<(&str, &str, &str, &str)> = vec![
        (
            "unknown key",
            "panhandle.yaml",
            "cpu: true\nnot_an_option: 1\n",
            "unknown field",
        ),
        (
            "unknown key",
            "panhandle.json",
            "{\"cpu\": true, \"not_an_option\": 1}",
            "unknown field",
        ),
        (
            "unsupported extension",
            "panhandle.toml",
            "cpu = true\n",
            "Unsupported config type",
        ),
        (
            "invalid YAML",
            "panhandle.yaml",
            "cpu: [unclosed\n",
            "Invalid YAML config",
        ),
        (
            "invalid JSON",
            "panhandle.json",
            "{\"cpu\": ",
            "Invalid JSON config",
        ),
        (
            "wrong value type",
            "panhandle.yaml",
            "poll: \"soon\"\n",
            "Invalid YAML config",
        ),
    ];
    for (case, name, body, message) in file_cases {
        let path = dir.path().join(name);
        fs::write(&path, body).unwrap();
        let mut cmd = Command::new(BIN);
        cmd.arg("--config").arg(&path);
        let r = spawn_and_collect(cmd, || {}, Duration::from_secs(5));
        let result = match r.exited {
            Some(code) if code != 0 => {
                expect(r.has(message), format!("rejected without '{message}'"))
            }
            other => Err(format!("not rejected ({other:?})")),
        };
        f.check(&format!("config rejects {case} ({name})"), result, Some(&r));
    }
    let mut cmd = Command::new(BIN);
    cmd.args(["--config", "/nonexistent/panhandle.yaml"]);
    let r = spawn_and_collect(cmd, || {}, Duration::from_secs(5));
    f.check(
        "config rejects a missing file",
        expect(
            r.exited.is_some_and(|c| c != 0) && r.has("Config file not found"),
            "not rejected with 'Config file not found'",
        ),
        Some(&r),
    );
    f.assert_none();
}
