# vaultify
![logo](docs/logo.png)

## Design considerations
- To keep the .secrets file parsing simple and less error prone we just support the v1 format
- Always try to fetch v2 secrets first and fallbacks to v1
- Spawning a process is only implemented on linux
- Organized, simple and maintainable codebase
- Zero unwraps (outside of tests)
- Fully vetted dependency tree
- Secret paths are specified in the same way as in the vault cli

## Usage
To get started simply create a .secrets file containing all the secrets you want vaultify to fetch.
The format of secrets is identical to the one used by the vault cli.

Take the following vault cli example:
```
vault kv put secret/production/third-party api-key=test-key1234
```
The corresponding vaultify `.secrets` file should look something like:
```
secret/production/third-party#api-key
```
Then simply start your program via vaultify (note that we could omit `--secrets-file` here):
```
vaultify --clear-env --secrets-file .secrets env
```
Ensure that `VAULT_ADDR`, `VAULT_TOKEN` or any of the cli-args is set correctly.

To see additional debug output set `export RUST_LOG=info`.

## Command line options
```
Usage: vaultify [OPTIONS] <CMD> [ARGS]...

Arguments:
  <CMD>      Command to run after fetching secrets
  [ARGS]...  Arguments to pass to <CMD>

Options:
      --host <HOST>
          Vault address (in the same format as vault-cli) [env: VAULT_ADDR=] [default: http://127.0.0.1:8200]
      --token <TOKEN>
          Authenticate via Vault access token [env: VAULT_TOKEN=]
      --github-token <GITHUB_TOKEN>
          Authenticate using Github personal access token. See https://developer.hashicorp.com/vault/docs/auth/github [env: VAULT_GITHUB_TOKEN=]
      --kubernetes-role <KUBERNETES_ROLE>
          Authenticate using Kubernetes service account in /var/run/secrets/kubernetes.io See https://developer.hashicorp.com/vault/docs/auth/kubernetes [env: VAULT_KUBERNETES_ROLE=]
      --secrets-file <SECRETS_FILE>
          [default: .secrets]
      --retries <RETRIES>
          Number of retries per query [default: 9]
      --retry-delay-ms <RETRY_DELAY_MS>
          Delay between retries (in ms) [default: 50]
      --concurrency <CONCURRENCY>
          Number of parallel requests to the vault [default: 8]
      --clear-env
          Clear the environment of the spawned process before spawning
  -h, --help
          Print help
  -V, --version
          Print version
```

## Local development
Start a local vault instance for testing:
```
# spawn a new vault dev server
vault server -dev

# setup environment
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN=[Root Token]

# put a key in vault
vault kv put secret/production/third-party api-key=test-key1234!?
vault kv get secret/production/third-party
```

Create a new secrets file, e.g. `.secrets` with the following content:
```
secret/production/third-party#api-key
```

As an example, run `env` through vaultify:
```
export RUST_LOG=info
cargo run -- --clear-env --attach env
```

`env` will output all configured secrets to your screen:
```
$ cargo run -- --clear-env --attach env
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/vaultify --clear-env --attach env`
PRODUCTION_THIRD_PARTY_API_KEY=key1234!?
```
