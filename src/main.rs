use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Parser;
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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
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
    #[arg(long, default_value = "9")]
    pub retries: usize,
    /// Delay between retries (in ms).
    #[arg(long, default_value = "50")]
    pub retry_delay_ms: u64,
    /// Number of parallel requests to the vault.
    #[arg(long, default_value = "8", value_parser = parse_positive_usize)]
    pub concurrency: usize,

    /// Clear the environment of the spawned process before spawning.
    #[arg(long, default_value = "false")]
    pub clear_env: bool,
}

fn parse_positive_usize(raw: &str) -> std::result::Result<usize, String> {
    let value = raw
        .parse::<usize>()
        .map_err(|e| format!("invalid concurrency value: {e}"))?;
    if value == 0 {
        return Err("concurrency must be greater than 0".to_string());
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // set default log level to warn
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("warn"));

    let args = Args::parse();

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

    // Safety: no other threads run at this point
    unsafe {
        process::spawn(
            args.cmd,
            &args.args,
            &env_secrets,
            process::SpawnOptions {
                clear_env: args.clear_env,
            },
        )?;
    }

    Ok(())
}

fn write_secret_to_file(path: &Path, value: &str, mode: u32, create: bool) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::IO(format!(
            "unable to resolve parent directory for file target {}",
            path.display()
        ))
    })?;

    if parent.exists() {
        if !parent.is_dir() {
            return Err(Error::IO(format!(
                "parent path is not a directory for file target {}",
                path.display()
            )));
        }
    } else if create {
        std::fs::create_dir_all(parent).map_err(|err| {
            Error::IO(format!(
                "unable to create parent directory {} for file target {}: {}",
                parent.display(),
                path.display(),
                err
            ))
        })?;
    } else {
        return Err(Error::IO(format!(
            "parent directory {} does not exist for file target {} (set create=true to create it)",
            parent.display(),
            path.display()
        )));
    }

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
