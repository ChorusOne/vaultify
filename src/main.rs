use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{ArgGroup, Parser};
#[cfg(target_os = "linux")]
use nix::libc::{O_CLOEXEC, O_NOFOLLOW};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

mod error;
mod process;
mod secrets;
mod vault;

use error::{Error, Result};
use secrets::SecretTarget;

const RETRIES_MAX: usize = 20;
const CONCURRENCY_MAX: usize = 64;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[command(group(
    ArgGroup::new("auth")
        .args(["token", "github_token", "kubernetes_role"])
        .multiple(false)
))]
struct Args {
    /// Vault address (in the same format as vault-cli).
    #[arg(long, env = "VAULT_ADDR", default_value = "http://127.0.0.1:8200")]
    pub host: String,
    /// Authenticate via Vault access token.
    #[arg(long, env = "VAULT_TOKEN")]
    token: Option<String>,
    /// Authenticate using Github personal access token.
    /// See https://developer.hashicorp.com/vault/docs/auth/github for more information.
    #[arg(long, env = "VAULT_GITHUB_TOKEN", verbatim_doc_comment)]
    github_token: Option<String>,
    /// Authenticate using Kubernetes service account in /var/run/secrets/kubernetes.io
    /// See https://developer.hashicorp.com/vault/docs/auth/kubernetes for more information.
    #[arg(long, env = "VAULT_KUBERNETES_ROLE", verbatim_doc_comment)]
    kubernetes_role: Option<String>,

    #[arg(long, default_value = ".secrets")]
    pub secrets_file: PathBuf,

    /// Command to run after fetching secrets.
    #[clap(index = 1)]
    pub cmd: String,
    /// Arguments to pass to <CMD>.
    #[clap(index = 2)]
    pub args: Vec<String>,

    /// Number of retries per query.
    #[arg(long, default_value = "3", value_parser = parse_retries)]
    pub retries: usize,
    /// Delay between retries (in ms).
    #[arg(long, default_value = "50")]
    pub retry_delay_ms: u64,
    /// Number of parallel requests to the vault.
    #[arg(long, default_value = "8", value_parser = parse_concurrency)]
    pub concurrency: usize,

    /// Clear the environment of the spawned process before spawning.
    #[arg(long, default_value = "false")]
    pub clear_env: bool,
}

fn parse_retries(raw: &str) -> std::result::Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|e| format!("invalid retries value: {e}"))?;
    if value > RETRIES_MAX {
        return Err(format!(
            "retries must be less than or equal to {}",
            RETRIES_MAX
        ));
    }

    Ok(value)
}

fn parse_concurrency(raw: &str) -> std::result::Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|e| format!("invalid concurrency value: {e}"))?;
    if value == 0 {
        return Err("concurrency must be greater than 0".to_string());
    }
    if value > CONCURRENCY_MAX {
        return Err(format!(
            "concurrency must be less than or equal to {}",
            CONCURRENCY_MAX
        ));
    }

    Ok(value)
}

enum AuthMethod {
    None,
    GitHub(String),
    Kubernetes(String),
    Token(String),
}

impl Args {
    pub fn auth_method(&self) -> AuthMethod {
        self.token
            .as_ref()
            .map(|v| AuthMethod::Token(v.clone()))
            .or_else(|| {
                self.kubernetes_role
                    .as_ref()
                    .map(|v| AuthMethod::Kubernetes(v.clone()))
            })
            .or_else(|| {
                self.github_token
                    .as_ref()
                    .map(|v| AuthMethod::GitHub(v.clone()))
            })
            .unwrap_or(AuthMethod::None)
    }
}

struct PreparedSpawn {
    cmd: String,
    args: Vec<String>,
    env_secrets: Vec<process::EnvSecret>,
    clear_env: bool,
}

fn main() -> Result<()> {
    // set default log level to warn
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("warn"));

    let args = Args::parse();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| Error::Execution(format!("unable to initialize tokio runtime: {}", err)))?;
    let prepared = runtime.block_on(prepare_spawn(args))?;
    drop(runtime);

    process::spawn(
        prepared.cmd,
        &prepared.args,
        &prepared.env_secrets,
        process::SpawnOptions {
            clear_env: prepared.clear_env,
        },
    )?;

    Ok(())
}

async fn prepare_spawn(args: Args) -> Result<PreparedSpawn> {
    // read secret spec file
    let secret_specs = match secrets::load_async(&args.secrets_file).await {
        Ok(specs) => specs,
        Err(err) => {
            println!("Error parsing secrets file: {err}");
            return Err(err);
        }
    };

    // get / fetch token
    let opts = vault::FetchTokenOpts {
        retries: args.retries,
        retry_delay: Duration::from_millis(args.retry_delay_ms),
    };
    let token = match vault::fetch_token(&args.host, args.auth_method(), opts).await {
        Ok(token) => token,
        Err(err) => {
            println!("Error getting vault token: {err}");
            return Err(err);
        }
    };

    // read secrets
    let opts = vault::FetchAllOpts {
        retries: args.retries,
        retry_delay: Duration::from_millis(args.retry_delay_ms),
        concurrency: args.concurrency,
    };
    let secrets = match vault::fetch_all(&args.host, token.as_deref(), &secret_specs, opts).await {
        Ok(secrets) => secrets,
        Err(err) => {
            println!("Error fetching secrets: {err}");
            return Err(err);
        }
    };

    let mut env_secrets = Vec::new();
    for secret in secrets.into_iter() {
        match secret.target {
            SecretTarget::Env { name } => env_secrets.push(process::EnvSecret {
                name,
                secret: secret.secret,
            }),
            SecretTarget::File { path, mode, create } => {
                write_secret_to_file(&path, &secret.secret, mode, create)?;
            }
        }
    }

    Ok(PreparedSpawn {
        cmd: args.cmd,
        args: args.args,
        env_secrets,
        clear_env: args.clear_env,
    })
}

fn write_secret_to_file(path: &Path, value: &str, mode: u32, create: bool) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::IO(format!(
            "unable to resolve parent directory for file target {}",
            path.display()
        ))
    })?;

    ensure_secure_parent_directory(parent, path, create)?;

    let path_exists = path.exists();
    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true);

    #[cfg(target_os = "linux")]
    {
        open_opts.custom_flags(O_NOFOLLOW | O_CLOEXEC).mode(mode);
    }

    if !path_exists {
        open_opts.create_new(true);
    }

    let mut file = open_opts
        .open(path)
        .map_err(|err| Error::IO(format!("unable to open {}: {}", path.display(), err)))?;

    let metadata = file.metadata().map_err(|err| {
        Error::IO(format!(
            "unable to read metadata for {}: {}",
            path.display(),
            err
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(Error::IO(format!(
            "refusing to write secret to non-regular file {}",
            path.display()
        )));
    }

    #[cfg(target_os = "linux")]
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|err| {
            Error::IO(format!(
                "unable to set file mode {:o} for {}: {}",
                mode,
                path.display(),
                err
            ))
        })?;

    file.set_len(0)
        .map_err(|err| Error::IO(format!("unable to truncate {}: {}", path.display(), err)))?;

    file.write_all(value.as_bytes())
        .map_err(|err| Error::IO(format!("unable to write {}: {}", path.display(), err)))?;

    Ok(())
}

fn ensure_secure_parent_directory(parent: &Path, target_path: &Path, create: bool) -> Result<()> {
    ensure_parent_directory_exists(parent, target_path, create)?;
    ensure_parent_has_no_symlink_components(parent, target_path)
}

fn ensure_parent_directory_exists(parent: &Path, target_path: &Path, create: bool) -> Result<()> {
    if parent.exists() {
        if parent.is_dir() {
            return Ok(());
        }

        return Err(Error::IO(format!(
            "parent path is not a directory for file target {}",
            target_path.display()
        )));
    }

    if !create {
        return Err(Error::IO(format!(
            "parent directory {} does not exist for file target {} (set create=true to create it)",
            parent.display(),
            target_path.display()
        )));
    }

    std::fs::create_dir_all(parent).map_err(|err| {
        Error::IO(format!(
            "unable to create parent directory {} for file target {}: {}",
            parent.display(),
            target_path.display(),
            err
        ))
    })
}

fn ensure_parent_has_no_symlink_components(parent: &Path, target_path: &Path) -> Result<()> {
    use std::path::Component;

    let mut current = if parent.is_absolute() {
        PathBuf::from(std::path::MAIN_SEPARATOR.to_string())
    } else {
        std::env::current_dir()
            .map_err(|err| Error::IO(format!("unable to get current directory: {}", err)))?
    };

    for component in parent.components() {
        match component {
            Component::Prefix(_) => {
                return Err(Error::IO(format!(
                    "unsupported path prefix in file target {}",
                    target_path.display()
                )))
            }
            Component::RootDir | Component::CurDir => continue,
            Component::ParentDir => {
                current.push("..");
            }
            Component::Normal(part) => {
                current.push(part);
            }
        }

        let metadata = std::fs::symlink_metadata(&current).map_err(|err| {
            Error::IO(format!(
                "unable to inspect parent directory component {} for file target {}: {}",
                current.display(),
                target_path.display(),
                err
            ))
        })?;

        if metadata.file_type().is_symlink() {
            return Err(Error::IO(format!(
                "refusing to write secret through symlinked parent component {} for file target {}",
                current.display(),
                target_path.display()
            )));
        }

        if !metadata.is_dir() {
            return Err(Error::IO(format!(
                "parent path component {} is not a directory for file target {}",
                current.display(),
                target_path.display()
            )));
        }
    }

    Ok(())
}
