use std::{future::Future, time::Duration};

use reqwest::Client;
use serde_json::Value;

use crate::{
    error::{Error, Result},
    secrets::{Secret, SecretSpec},
    Args,
};

/// Fetches a list of secrets from vault with retry and batching.
pub async fn fetch_all(args: &Args, secrets: &[SecretSpec]) -> Result<Vec<Secret>> {
    let mut results = Vec::new();

    let retry_delay_ms = Duration::from_millis(args.retry_delay_ms);

    for secrets in secrets.chunks(args.concurrency) {
        let res = futures::future::join_all(secrets.iter().map(|s| async {
            retry(
                || async { fetch_single(args, s).await },
                args.retries,
                retry_delay_ms,
            )
            .await
        }))
        .await;
        for r in res.into_iter() {
            results.push(r?);
        }
    }

    Ok(results)
}

/// Fetches a single secret from vault v2 and fallbacks to vault v1 on error.
pub async fn fetch_single(args: &Args, secret: &SecretSpec) -> Result<Secret> {
    // try to fetch a v2 secret
    match fetch_single_v2(args, secret).await {
        Ok(secret) => return Ok(secret),
        Err(err) => log::warn!(
            "could not fetch v2 secret `{}` from vault: {}",
            secret.name(),
            err
        ),
    };

    // fallback to fetching a v1 secret
    match fetch_single_v1(args, secret).await {
        Ok(secret) => Ok(secret),
        Err(err) => {
            log::warn!(
                "could not fetch v1 secret `{}` from vault: {}",
                secret.name(),
                err
            );
            Err(err)
        }
    }
}

async fn fetch_single_v2(args: &Args, secret_spec: &SecretSpec) -> Result<Secret> {
    let vault_url = format!(
        "{}/v1/{}/data/{}",
        args.host, secret_spec.mount, secret_spec.path
    );
    let secret_name = secret_spec.name();
    log::info!("fetching v2 secret `{}` from `{}`", secret_name, vault_url);

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
    let value = serde_json::from_str::<Value>(&result)?;
    let data = value
        .get("data")
        .ok_or_else(|| Error::NotFound("vault response does not contain .data".to_string()))?;
    let data = data
        .get("data")
        .ok_or_else(|| Error::NotFound("vault response does not contain .data.data".to_string()))?;
    let secret_value = data
        .get(&secret_spec.secret)
        .ok_or_else(|| {
            Error::NotFound(format!(
                "vault response does not contain .data.data.{}",
                secret_spec.secret
            ))
        })?
        .as_str()
        .ok_or_else(|| {
            Error::Deserialization(
                "vault response secret cannot be made into a string or is empty".to_string(),
            )
        })?;

    Ok(Secret {
        name: secret_name,
        secret: secret_value.to_string(),
    })
}

async fn fetch_single_v1(args: &Args, secret_spec: &SecretSpec) -> Result<Secret> {
    let vault_url = format!(
        "{}/v1/{}/{}",
        args.host, secret_spec.mount, secret_spec.path
    );
    let secret_name = secret_spec.name();
    log::info!("fetching v1 secret `{}` from `{}`", secret_name, vault_url);

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
    let value = serde_json::from_str::<Value>(&result)?;
    let data = value
        .get("data")
        .ok_or_else(|| Error::NotFound("vault response does not contain .data".to_string()))?;
    let secret_value = data
        .get(&secret_spec.secret)
        .ok_or_else(|| {
            Error::NotFound(format!(
                "vault response does not contain .data.{}",
                secret_spec.secret
            ))
        })?
        .as_str()
        .ok_or_else(|| {
            Error::Deserialization(
                "vault response secret cannot be made into a string or is empty".to_string(),
            )
        })?;

    Ok(Secret {
        name: secret_name,
        secret: secret_value.to_string(),
    })
}

async fn retry<T, F, FU>(op: F, count: usize, delay: Duration) -> Result<T>
where
    F: Fn() -> FU,
    FU: Future<Output = Result<T>>,
{
    for _ in 0..=count {
        match op().await {
            Ok(result) => return Ok(result),
            Err(err) => {
                log::warn!("operation failed, retrying: {}", err);
            }
        }

        tokio::time::sleep(delay).await;
    }

    Err(Error::MaxRetries)
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
