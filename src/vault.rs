use std::time::Duration;

use reqwest::Client;
use serde_json::{Map, Value};
use tracing::{error, info};

use crate::{error::Result, secrets::Secret, Args};

pub async fn fetch_single_v2(args: &Args, secret: &Secret) -> Result<String> {
    // TODO: url scheme
    let vault_url = format!("{}/v1/{}/data/{}", args.host, secret.mount, secret.path);
    let secret_name = secret.name();
    println!("fetching v2 secret `{}` from `{}`", secret_name, vault_url);

    // TODO: allow reading from ~/.vault_token as fallback
    let vault_token = &args.token;

    // TODO: create client with timeouts
    let result = client()
        .get(vault_url)
        .header("X-Vault-Token", vault_token)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    // parse json blob dynamically
    let resultjson = serde_json::from_str::<Value>(&result).unwrap();
    let data = resultjson.get("data").unwrap();
    let data = data.get("data").unwrap();
    let secret_value = data.get(&secret.secret).unwrap().as_str().unwrap();
    //println!("result: {:?}", secret);

    Ok(secret_value.to_string())
}

pub async fn fetch_single_v1(args: &Args, secret: &Secret) -> Result<String> {
    // TODO: url scheme
    let vault_url = format!("{}/v1/{}/{}", args.host, secret.mount, secret.path);
    let secret_name = secret.name();
    println!("fetching v1 secret `{}` from `{}`", secret_name, vault_url);

    // TODO: allow reading from ~/.vault_token as fallback
    let vault_token = &args.token;

    // TODO: create client with timeouts
    let result = client()
        .get(vault_url)
        .header("X-Vault-Token", vault_token)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    // parse json blob dynamically
    let resultjson = serde_json::from_str::<Value>(&result).unwrap();
    let data = resultjson.get("data").unwrap();
    let secret_value = data.get(&secret.secret).unwrap().as_str().unwrap();
    //println!("result: {:?}", secret);

    Ok(secret_value.to_string())
}

fn client() -> Client {
    const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
    const DEFAULT_REQUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

    Client::builder()
        .timeout(DEFAULT_REQUEST_TIMEOUT)
        .connect_timeout(DEFAULT_REQUEST_CONNECT_TIMEOUT)
        .build()
        .expect("unable to build reqwest client")
}
