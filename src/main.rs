use std::path::PathBuf;

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
    /// Vault access token.
    #[arg(long, env = "VAULT_TOKEN")]
    pub token: String,
    #[arg(long, default_value = ".secrets")]
    pub secrets_file: PathBuf,

    /// Command to run after fetching secrets.
    #[clap(index = 1)]
    pub cmd: String,
    /// Arguments to pass to <CMD>.
    #[clap(index = 2)]
    pub args: Vec<String>,

    /// Number of retries per query
    #[arg(long, default_value = "9")]
    pub retries: usize,
    /// Delay between retries (in ms)
    #[arg(long, default_value = "50")]
    pub retry_delay_ms: u64,
    /// Number of parallel requests to the vault.
    #[arg(long, default_value = "8")]
    pub concurrency: usize,

    /// Clear the environment of the spawned process before spawning.
    #[arg(long, default_value = "false")]
    pub clear_env: bool,
    /// Keep the spawned process attached as a child of the `vaultify` process.
    #[arg(long, short = 'd', default_value = "false")]
    pub attach: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // TODO: check if args.host is a valid URL
    // TODO: custom .secrets

    let secs = secrets::load_async(&args.secrets_file).await.unwrap();
    let secrets = vault::fetch_all(&args, &secs).await.unwrap();

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
