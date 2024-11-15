use std::{future::Future, time::Duration};

use lazy_static::lazy_static;
use reqwest::{
    header::{HeaderMap, CONTENT_TYPE},
    Client,
};
use serde_json::Value;

use crate::{
    error::{Error, Result},
    secrets::{Secret, SecretSpec},
    AuthMethod,
};

lazy_static! {
    static ref HEADERS_JSON: HeaderMap = {
        let mut headers = HeaderMap::with_capacity(1);
        headers.insert(
            CONTENT_TYPE,
            "application/json".parse().expect("invalid header value"),
        );
        headers
    };
}

/// Options passed to `fetch_token`.
pub struct FetchTokenOpts {
    /// Number of retries per query.
    pub retries: usize,
    /// Delay between retries.
    pub retry_delay: Duration,
}

/// Fetches the vault token or returns it depending on the `AuthMethod`.
pub async fn fetch_token(
    host: &str,
    auth_method: AuthMethod,
    opts: FetchTokenOpts,
) -> Result<Option<String>> {
    match auth_method {
        AuthMethod::None => Ok(None),
        AuthMethod::GitHub(pat) => {
            retry(
                || async { fetch_token_github(host, &pat).await.map(Some) },
                opts.retries,
                opts.retry_delay,
            )
            .await
        }
        AuthMethod::Kubernetes(role) => {
            retry(
                || async { fetch_token_kubernetes(host, &role).await.map(Some) },
                opts.retries,
                opts.retry_delay,
            )
            .await
        }
        AuthMethod::Token(token) => Ok(Some(token)),
    }
}

/// Fetches a vault token via a GitHub personal access token.
async fn fetch_token_github(host: &str, pat: &str) -> Result<String> {
    let vault_url = format!("{host}/v1/auth/github/login");
    log::info!("fetching token via github from `{}`", vault_url);

    // setup body
    let body = serde_json::json!({
        "token": pat,
    });

    // send request
    let response = client()
        .post(vault_url.clone())
        .headers(HEADERS_JSON.clone())
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        let result = response.text().await?;
        return Err(Error::Reqwest(format!(
            "HTTP status server error ({}) for url ({}): {}",
            status, vault_url, result
        )));
    }

    // read `.auth.client_token` from response
    let result = response.text().await?;
    let value = serde_json::from_str::<Value>(&result)?;
    let data = value
        .get("auth")
        .ok_or_else(|| Error::NotFound("vault response does not contain .auth".to_string()))?;
    let token = data
        .get("client_token")
        .ok_or_else(|| {
            Error::NotFound("vault response does not contain .data.client_token".to_string())
        })?
        .as_str()
        .ok_or_else(|| {
            Error::Deserialization(
                "vault response token cannot be made into a string or is empty".to_string(),
            )
        })?;

    Ok(token.to_string())
}

/// Fetches a vault token via a Kubernetes role.
async fn fetch_token_kubernetes(host: &str, role: &str) -> Result<String> {
    // read service account jwt
    const KUBE_SA_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    let jwt = tokio::fs::read_to_string(KUBE_SA_TOKEN)
        .await
        .map_err(|err| Error::IO(format!("unable to read file {:?}: {}", KUBE_SA_TOKEN, err)))?;

    let vault_url = format!("{host}/v1/auth/kubernetes/login");
    log::info!("fetching token via kubernetes role from `{}`", vault_url);

    // setup body
    let body = serde_json::json!({
        "jwt": jwt,
        "role": role,
    });

    // send request
    let response = client()
        .post(vault_url.clone())
        .headers(HEADERS_JSON.clone())
        .json(&body)
        .send()
        .await?;

    let status = response.status();
    if status.is_client_error() || status.is_server_error() {
        let result = response.text().await?;
        return Err(Error::Reqwest(format!(
            "HTTP status server error ({}) for url ({}): {}",
            status, vault_url, result
        )));
    }

    // read `.auth.client_token` from response
    let result = response.text().await?;
    let value = serde_json::from_str::<Value>(&result)?;
    let data = value
        .get("auth")
        .ok_or_else(|| Error::NotFound("vault response does not contain .auth".to_string()))?;
    let token = data
        .get("client_token")
        .ok_or_else(|| {
            Error::NotFound("vault response does not contain .data.client_token".to_string())
        })?
        .as_str()
        .ok_or_else(|| {
            Error::Deserialization(
                "vault response token cannot be made into a string or is empty".to_string(),
            )
        })?;

    Ok(token.to_string())
}

/// Options passed to `fetch_all`.
pub struct FetchAllOpts {
    /// Number of retries per query.
    pub retries: usize,
    /// Delay between retries.
    pub retry_delay: Duration,
    /// Number of parallel requests to the vault.
    pub concurrency: usize,
}

/// Fetches a list of secrets from vault with retry and batching.
pub async fn fetch_all(
    host: &str,
    token: Option<&str>,
    secrets: &[SecretSpec],
    opts: FetchAllOpts,
) -> Result<Vec<Secret>> {
    let mut results = Vec::new();

    for secrets in secrets.chunks(opts.concurrency) {
        let res = futures::future::join_all(secrets.iter().map(|s| async {
            retry(
                || async { fetch_single(host, token, s).await },
                opts.retries,
                opts.retry_delay,
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
pub async fn fetch_single(host: &str, token: Option<&str>, secret: &SecretSpec) -> Result<Secret> {
    // try to fetch a v2 secret
    match fetch_single_v2(host, token, secret).await {
        Ok(secret) => return Ok(secret),
        Err(err) => log::warn!(
            "could not fetch v2 secret `{}` from vault: {}",
            secret.name(),
            err
        ),
    };

    // fallback to fetching a v1 secret
    match fetch_single_v1(host, token, secret).await {
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

async fn fetch_single_v2(
    host: &str,
    vault_token: Option<&str>,
    secret_spec: &SecretSpec,
) -> Result<Secret> {
    let vault_url = format!(
        "{}/v1/{}/data/{}",
        host, secret_spec.mount, secret_spec.path
    );
    let secret_name = secret_spec.name();
    log::info!("fetching v2 secret `{}` from `{}`", secret_name, vault_url);

    let mut client = client().get(vault_url);
    if let Some(vault_token) = vault_token {
        client = client.header("X-Vault-Token", vault_token)
    }
    let result = client.send().await?.error_for_status()?.text().await?;

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

async fn fetch_single_v1(
    host: &str,
    vault_token: Option<&str>,
    secret_spec: &SecretSpec,
) -> Result<Secret> {
    let vault_url = format!("{}/v1/{}/{}", host, secret_spec.mount, secret_spec.path);
    let secret_name = secret_spec.name();
    log::info!("fetching v1 secret `{}` from `{}`", secret_name, vault_url);

    let mut client = client().get(vault_url);
    if let Some(vault_token) = vault_token {
        client = client.header("X-Vault-Token", vault_token)
    }
    let result = client.send().await?.error_for_status()?.text().await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_headers_json() {
        assert_eq!(HEADERS_JSON.clone().len(), 1);
    }
}
