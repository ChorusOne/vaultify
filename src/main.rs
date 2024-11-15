use std::{path::PathBuf, time::Duration};

use clap::Parser;

mod error;
mod process;
mod secrets;
mod vault;

use error::Result;

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
    #[arg(long, default_value = "8")]
    pub concurrency: usize,

    /// Clear the environment of the spawned process before spawning.
    #[arg(long, default_value = "false")]
    pub clear_env: bool,
    /// Keep the spawned process attached as a child of the `vaultify` process.
    #[arg(long, short = 'a', default_value = "false")]
    pub attach: bool,
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

#[tokio::main]
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

    process::spawn(
        args.cmd,
        &args.args,
        &secrets,
        process::SpawnOptions {
            clear_env: args.clear_env,
            detach: !args.attach,
        },
    )?;

    Ok(())
}
