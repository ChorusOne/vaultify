# vaultify
![logo](docs/logo.png)

## Design considerations
- To keep the .secrets file parsing simple and less error prone we just support the v1 format
- Always try to fetch v2 secrets first and fallbacks to v1
- Spawning a process is only implemented on linux
- Orgnaized, simple and maintainable codebase
- Zero unwraps (outside of tests)
- Fully vetted
- Secret paths are specified in the same way as in the vault cli

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

Create a new secrets file, e.g. `test.secrets` with the following content:
```
secret/production/third-party#api-key
```

As an example, run `env` through vaultify:
```
cargo run -- --clear-env env
```

`env` will output all configured secrets to your screen:
```
$ cargo run -- --clear-env env
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.06s
     Running `target/debug/vaultify env`
PRODUCTION_THIRD_PARTY_API_KEY=key1234!?
```
