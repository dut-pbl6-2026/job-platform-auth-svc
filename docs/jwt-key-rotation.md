# JWT signing key: generation, storage and rotation

Access tokens are RS256. auth-svc signs with one private key (`Jwt__SigningKeyPem`). Every other service
validates with the public keys that auth-svc publishes at `/.well-known/jwks.json`, found through
`/.well-known/openid-configuration`. Validators never hold the private key.

Never print the key, paste it into a chat or a ticket, or commit it. Keep it only in the secret store.

## Format

`JWT_SIGNING_KEY_PEM` (infra env) and `Jwt__SigningKeyPem` (auth-svc) hold the **base64 of a PKCS#8 PEM** RSA
private key, 2048 bits or more, on one line.

Generate (writes nothing to the repo; pipe the result straight into the secret store):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 -w0
```

Dev: `mise run sync-env` in job-platform-infra generates the key into `envs/.env.dev` when the placeholder is
still present. Prod: the key lives in Infisical, environment `prod`, name `JWT_SIGNING_KEY_PEM`. `sync-env-prod`
refuses placeholder values.

## Where it is used

| Setting | Who | Meaning |
|---|---|---|
| `Jwt__SigningKeyPem` | auth-svc only | active private key, signs access tokens |
| `Jwt__PreviousPublicKeys__N` | auth-svc only | base64 of SPKI PEM public keys still published (rotation overlap) |
| `Jwt__MetadataAddress` | every validator | `http://auth:5001/.well-known/openid-configuration` |

`kid` is the RFC 7638 thumbprint of the public key, so no separate kid value is configured.

## Rotation without downtime

Validators refresh their key set at most every 15 minutes, and immediately on an unknown `kid`. Access
tokens live 15 minutes. Use the three phases in this order.

1. **Publish the new public key.** Generate the new key pair. Add the **new public key** (SPKI PEM,
   base64) to `Jwt__PreviousPublicKeys__0` on auth-svc, keep the current signing key unchanged, and deploy.
   Wait at least 30 minutes so every validator has loaded it.
2. **Switch signing.** Set `Jwt__SigningKeyPem` to the new private key and move the old public key into
   `Jwt__PreviousPublicKeys__1`. Deploy. Tokens signed with the old key still validate because it is still
   published.
3. **Retire the old key.** After 30 minutes (access-token TTL 15 minutes plus validator refresh), remove
   the old public key from `Jwt__PreviousPublicKeys__*` and deploy.

Rollback between phases: restore the previous `Jwt__SigningKeyPem` and remove the new public key from the
list. Tokens issued with the new key stop validating once it is unpublished, which is expected.

## Emergency rotation (suspected leak)

Skip the overlap: replace `Jwt__SigningKeyPem`, clear `Jwt__PreviousPublicKeys__*`, and deploy. Every access
token stops validating within the validator refresh window (at most 15 minutes). Clients then refresh (refresh
tokens are opaque DB rows) and receive new access tokens. Revoke sessions for affected users if the leak
scope is unknown.

## Checks after any change

- `GET /.well-known/jwks.json` returns only public members (`kty`, `use`, `alg`, `kid`, `n`, `e`), with one entry
  per key that must still validate.
- A token signed with the new key is accepted by a validator after its refresh.
- No `d`, `p`, `q`, `dp`, `dq` or `qi` member appears anywhere in the response.
