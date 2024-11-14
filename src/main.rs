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
    host: String,
    /// Vault access token.
    #[arg(long, env = "VAULT_TOKEN")]
    token: String,

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
    /// The detach the spawned process from the `vaultify` process.
    #[arg(long, short = 'd', default_value = "true")]
    pub detach: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    // TODO: check if args.host is a valid URL
    // TODO: custom .secrets

    let secs = secrets::load_async("./test.secrets").await.unwrap();
    let secrets = vault::fetch_all(&args, &secs).await.unwrap();

    process::spawn(
        args.cmd,
        &args.args,
        &secrets,
        process::SpawnOptions {
            clear_env: args.clear_env,
            detach: args.detach,
        },
    )?;

    Ok(())
}
