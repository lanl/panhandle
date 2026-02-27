use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

//struct for the cli arguments / make them as layerable as possible
///Panhandle provides the ability to monitor execve syscalls to identify specific interesting user behavior,
///    as well as the ability to monitor specific shells (bash, zsh, and fmsh) on a linux host.
///    Several optional filters enable an administrator to selectively apply criterion to examine
///    desired user behavior. These include UID filtering as well as filtering for the use of specific executables.
///    Specified events are logged for further reporting and/or analysis. Logging options include file, http, syslog,
///    or terminal output for selected events.
#[derive(Parser, Debug, Clone, Deserialize, PartialEq, Default)]
#[command(
    version,
    about,
    author("Skip McGee"),
    propagate_version = true,
    subcommand_required = false,
    subcommand_negates_reqs = false
)]
pub struct RawArgs {
    /// Monitor events from the bash shell using the readline function.
    #[arg(short, long, global = true)]
    #[serde(default)]
    pub bash: bool,

    /// Invalidates json option and returns output to help identify why the program might not pick up on desired events.
    #[arg(short, long, global = true)]
    #[serde(default)]
    pub debug: bool,

    /// Pass arguments from a config file in YAML or JSON, the default config file is located at /opt/panhandle/panhandle.yaml. Arguments provided in the command line will overwrite those given in the config file.
    #[arg(short, long, global = true)]
    pub config: Option<String>,

    /// Exclude a range of uids from monitoring, specify the MINIMUM uid of the range. Defaults to 1.
    #[arg(long, value_parser(clap::value_parser!(u32)), global = true)]
    pub exclude_min_uid: Option<u32>,

    /// Exclude a range of uids from monitoring, specify the MAXIMUM uid of the range. Defaults to 999.
    #[arg(long, value_parser(clap::value_parser!(u32)), global = true)]
    pub exclude_max_uid: Option<u32>,

    /// Specify a comma separated list of absolute executable paths to exclusively monitor. Maximum limit is 10.
    #[arg(short, long, value_parser, num_args = 1.., value_delimiter = ',', global = true)]
    pub executables: Option<Vec<String>>,

    /// Monitor events from the fmsh shell using the readline function. This also returns events from the bash shell as fmsh is a derivative of bash.
    #[arg(short, long, global = true)]
    #[serde(default)]
    pub fmsh: bool,

    /// Subcommand to specify the type of output desired, see the --syslog, --http, or --file options.
    #[command(subcommand)]
    pub output: Option<OutputCommand>,

    /// Only include events from the specified uid(s), can be a comma separated list. Maximum limit is 10.
    #[arg(long, value_parser, num_args = 1.., value_delimiter = ',', global = true)]
    pub include_uid: Option<Vec<String>>,

    /// Output events as valid json strings separated by newlines.
    #[arg(short, long, global = true)]
    #[serde(default)]
    pub json: bool,

    /// Omit logging stdout to the terminal.
    #[arg(short, long, global = true)]
    #[serde(default)]
    pub quiet: bool,

    /// Monitor events from the execve syscall. This is the program default if no other arguments are selected.
    #[arg(short, long, global = true)]
    #[serde(default)]
    pub syscall_execve: bool,

    /// Output execve syscall events only from the shells: bash, tcsh, zsh & fmsh. This does not effect the output of the bash or zsh options.
    #[arg(long, global = true)]
    #[serde(default)]
    pub shells: bool,

    /// Verbose output.
    #[arg(short, long, global = true)]
    #[serde(default)]
    pub verbose: bool,

    /// Monitor events from the zsh shell using the zlentry function.
    #[arg(short, long, global = true)]
    #[serde(default)]
    pub zsh: bool,
}

// output parent command with syslog, http, and file subcommands
// example usage: output --syslog --file test.log -h myserver
#[derive(Debug, Subcommand, Clone, Deserialize, Serialize, PartialEq)]
pub enum OutputCommand {
    /// Output options: --file, --http, --syslog.
    #[command(name = "output")]
    Output {
        /// Specify the absolute path to the desired log file.
        #[arg(long, value_name = "FILE")]
        file: Option<std::path::PathBuf>,

        /// Output events to the specified HTTP endpoint.
        #[arg(long)]
        http: Option<String>,

        /// Output events to syslog. Can be done locally or remotely.
        #[arg(long, num_args(0..=1),
        long_help = r"Output events to syslog. Local or remote options are supported.
        Local example: --syslog /dev/log or --syslog unix or --syslog
        Remote TCP example: --syslog hpcsyslog.lanl.gov:514/tcp
        Remote UDP example: --syslog hpcsyslog.lanl.gov:514/udp",
        )]
        syslog: Option<Option<String>>,
    },
}

#[derive(Debug, Deserialize, Default, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfigArgs {
    #[serde(default)]
    pub verbose: bool,

    #[serde(default)]
    pub json: bool,

    #[serde(default)]
    pub debug: bool,

    pub exclude_min_uid: Option<u32>,
    pub exclude_max_uid: Option<u32>,
    pub executables: Option<Vec<String>>,

    #[serde(default)]
    pub bash: bool,

    #[serde(default)]
    pub fmsh: bool,

    #[serde(default)]
    pub zsh: bool,

    #[serde(default)]
    pub quiet: bool,

    #[serde(default)]
    pub syscall_execve: bool,

    #[serde(default)]
    pub shells: bool,

    // list-based output format to promote hyphen key:value pair syntax in config files
    pub output: Option<Vec<OutputConfig>>,

    pub include_uid: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(untagged, deny_unknown_fields)]
pub enum OutputConfig {
    File { file: std::path::PathBuf },
    Http { http: String },
    Syslog { syslog: Option<Option<String>> },
}

// into function to convert structure of config args to structure of cli args, as main is expecting
impl From<ConfigArgs> for RawArgs {
    fn from(cfg: ConfigArgs) -> Self {
        // Convert output vector into CLI OutputCommand
        let output = cfg.output.map(|vec| {
            let mut file: Option<std::path::PathBuf> = None;
            let mut http: Option<String> = None;
            let mut syslog: Option<Option<String>> = None;

            for o in vec {
                match o {
                    OutputConfig::File { file: f } => file = Some(f),
                    OutputConfig::Http { http: h } => http = Some(h),
                    OutputConfig::Syslog { syslog: s } => syslog = s,
                }
            }

            OutputCommand::Output { file, http, syslog }
        });

        RawArgs {
            // Copy all simple fields
            verbose: cfg.verbose,
            debug: cfg.debug,
            json: cfg.json,
            shells: cfg.shells,
            syscall_execve: cfg.syscall_execve,
            bash: cfg.bash,
            fmsh: cfg.fmsh,
            zsh: cfg.zsh,
            quiet: cfg.quiet,
            exclude_min_uid: cfg.exclude_min_uid,
            exclude_max_uid: cfg.exclude_max_uid,
            executables: cfg.executables,
            include_uid: cfg.include_uid,
            // output subcommand
            output,
            config: None,
        }
    }
}

// function to load all args given. Merges config and cli args with cli args overwriting those given in the config file.
pub async fn merge_args(cli_args: RawArgs, config_args: ConfigArgs) -> RawArgs {
    let mut final_args = config_args.clone();

    // Override bool fields with CLI args if present
    final_args.debug = cli_args.debug || config_args.debug;
    final_args.verbose = cli_args.verbose || config_args.verbose;
    final_args.bash = cli_args.bash || config_args.bash;
    final_args.fmsh = cli_args.fmsh || config_args.fmsh;
    final_args.zsh = cli_args.zsh || config_args.zsh;
    final_args.json = cli_args.json || config_args.json;
    final_args.quiet = cli_args.quiet || config_args.quiet;
    final_args.shells = cli_args.shells || config_args.shells;
    final_args.syscall_execve = cli_args.syscall_execve || config_args.syscall_execve;

    // Override non-bools with CLI args if present
    if cli_args.exclude_min_uid.is_some() {
        final_args.exclude_min_uid = cli_args.exclude_min_uid;
    }
    if cli_args.exclude_max_uid.is_some() {
        final_args.exclude_max_uid = cli_args.exclude_max_uid;
    }
    if cli_args.executables.is_some() {
        final_args.executables = cli_args.executables.clone();
    }
    if cli_args.include_uid.is_some() {
        final_args.include_uid = cli_args.include_uid.clone();
    }

    // Merge CLI output into config output, or create it if missing
    if let Some(OutputCommand::Output {
        file: cli_file,
        http: cli_http,
        syslog: cli_syslog,
    }) = &cli_args.output
    {
        let mut outputs = final_args.output.take().unwrap_or_default();

        // Merge or add new outputs
        if outputs.is_empty() {
            if let Some(f) = cli_file {
                outputs.push(OutputConfig::File { file: f.clone() });
            }
            if let Some(h) = cli_http {
                outputs.push(OutputConfig::Http { http: h.clone() });
            }
            if cli_syslog.is_some() {
                outputs.push(OutputConfig::Syslog {
                    syslog: cli_syslog.clone(),
                });
            }
        } else {
            for output in outputs.iter_mut() {
                match output {
                    OutputConfig::File { file } => {
                        if let Some(f) = cli_file {
                            *file = f.clone();
                        }
                    }
                    OutputConfig::Http { http } => {
                        if let Some(h) = cli_http {
                            *http = h.clone();
                        }
                    }
                    OutputConfig::Syslog { syslog } => {
                        if cli_syslog.is_some() {
                            *syslog = cli_syslog.clone();
                        }
                    }
                }
            }
        }

        if !outputs.is_empty() {
            final_args.output = Some(outputs);
        }
    }

    // .into() is implemented so that type RawArgs is returned
    final_args.into()
}

// load any arguments given in config file into ConfigArgs struct
pub async fn load_config_args(config_path: String) -> Result<ConfigArgs, String> {
    // Load config file if provided
    let path = config_path;
    let path_ref = Path::new(&path);
    if !path_ref.exists() {
        return Err(format!("Config file not found: {}", path));
    }

    let contents = fs::read_to_string(path_ref)
        .unwrap_or_else(|e| format!("Failed to read config file {}: {}", path, e));

    // store deserialized config args
    match path_ref.extension().and_then(|e| e.to_str()) {
        Some("json") => serde_json::from_str(&contents)
            .map_err(|e| format!("Invalid JSON config {}: {}", path, e)),
        Some("yaml") | Some("yml") => serde_yaml::from_str(&contents)
            .map_err(|e| format!("Invalid YAML config {}: {}", path, e)),
        other => Err(format!("Unsupported config type {:?}", other)),
    }
}
