use clap::{Parser, Subcommand};

mod error;
mod process;
mod secrets;
mod vault;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Vault host, either an IP address or DNS name.
    #[arg(long, env = "VAULT_HOST", default_value = "http://127.0.0.1:8200")]
    host: String,
    // port
    // addr
    /// Token to authenticate to Vault with.
    #[arg(long, env = "VAULT_TOKEN")]
    token: String,

    /// Command to run after fetching secrets.
    #[clap(index = 1)]
    pub cmd: String,
    /// Arguments to pass to <CMD>.
    #[clap(index = 2)]
    pub args: Vec<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    println!("{:?}", args);

    // TODO: check if args.host is a valid URL

    let secs = secrets::load("./test.secrets").unwrap();
    let secrets = vault::fetch_all(&args, &secs).await.unwrap();
    process::spawn(
        args.cmd,
        &args.args,
        &secrets,
        process::SpawnOptions {
            clear_env: true,
            detach: false,
        },
    );
}
