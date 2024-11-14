use clap::{Parser, Subcommand};

mod error;
mod process;
mod secrets;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Vault host, either an IP address or DNS name.
    #[arg(long, env = "VAULT_HOST", default_value = "localhost")]
    host: String,
    // port
    // addr
    /// Token to authenticate to Vault with.
    #[arg(long, env = "VAULT_TOKEN")]
    token: Option<String>,

    /// Command to run after fetching secrets.
    #[clap(index = 1)]
    pub cmd: String,
    /// Arguments to pass to <CMD>.
    #[clap(index = 2)]
    pub args: Vec<String>,
}

fn main() {
    let args = Args::parse();
    println!("{:?}", args);

    // TODO: check if args.host is a valid URL

    process::spawn(
        args.cmd,
        &args.args,
        process::SpawnOptions {
            clear_env: true,
            detach: false,
        },
    );
}
