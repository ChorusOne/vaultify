use std::time::Duration;

use reqwest::Client;
use serde_json::{Map, Value};
use tracing::{error, info};

use crate::{
    error::Result,
    secrets::{Secret, SecretSpec},
    Args,
};

pub async fn fetch_all(args: &Args, secrets: &[SecretSpec]) -> Result<Vec<Secret>> {
    // TODO: configurable batch, timeout, etc.

    let mut results = Vec::new();

    // TODO: retry!
    for secrets in secrets.chunks(args.concurrency) {
        let res = futures::future::join_all(
            secrets
                .iter()
                .map(|s| async { fetch_single(args, s).await }),
        )
        .await;
        for r in res.into_iter() {
            results.push(r?);
        }
    }

    Ok(results)
}

pub async fn fetch_single(args: &Args, secret: &SecretSpec) -> Result<Secret> {
    // try to fetch a v2 secret
    if let Ok(secret) = fetch_single_v2(args, secret).await {
        return Ok(secret);
    }

    // fallback to fetching a v1 secret
    fetch_single_v1(args, secret).await
}

async fn fetch_single_v2(args: &Args, secret_spec: &SecretSpec) -> Result<Secret> {
    // TODO: url scheme
    let vault_url = format!(
        "{}/v1/{}/data/{}",
        args.host, secret_spec.mount, secret_spec.path
    );
    let secret_name = secret_spec.name();
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
    let secret_value = data.get(&secret_spec.secret).unwrap().as_str().unwrap();
    //println!("result: {:?}", secret);

    Ok(Secret {
        name: secret_name,
        secret: secret_value.to_string(),
    })
}

async fn fetch_single_v1(args: &Args, secret_spec: &SecretSpec) -> Result<Secret> {
    // TODO: url scheme
    let vault_url = format!(
        "{}/v1/{}/{}",
        args.host, secret_spec.mount, secret_spec.path
    );
    let secret_name = secret_spec.name();
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
    let secret_value = data.get(&secret_spec.secret).unwrap().as_str().unwrap();
    //println!("result: {:?}", secret);

    Ok(Secret {
        name: secret_name,
        secret: secret_value.to_string(),
    })
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
