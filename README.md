# vaultify
![logo](docs/logo.png)

## Design considerations
- To keep the .secrets file parsing simple and less error prone we just support the v1 format
- For now spawning a process is only implemented on linux
- Keeping the codebase organized, simple and maintainable
- Secret paths are specified in the same way as in the vault cli
- This tool always try to fetch v2 secrets first and fallbacks to v1

## Local development
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
