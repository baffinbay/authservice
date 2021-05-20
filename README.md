# authservice

## Testing

 1. Install Vault server from https://www.vaultproject.io/.
 1. Run `/usr/bin/vault server -dev` and keep it open while developing.
 1. Enable SSH certificate engine:

    ```
    VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable -path=ssh ssh
    VAULT_ADDR=http://127.0.0.1:8200 vault write ssh/roles/user - < ssh.policy
    ```

 1. Generate a renewable token to use:

    ```
    VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=$(cat "${HOME}/.vault-token") \
      vault token create -renewable -ttl=48h -format=json \
      | jq -r '.auth.client_token' > vault.token

    ```
 1. Start authservice using `VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN="$(cat vault.token)" ./authservice`
