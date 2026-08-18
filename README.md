# aws-sts-stub

For local development and testing only, never for production: the signing
keys are committed and public, so anyone holding them can mint a token
asserting any identity.

A stub of the AWS STS [`GetWebIdentityToken`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html)
API, so services that authenticate to each other with AWS Web Identity tokens
can run locally and in test harnesses without AWS.

It implements one operation, plus the OpenID discovery and JWKS endpoints
needed to verify what it mints. LocalStack and moto do not implement this
operation, which is why this exists.

## What it does

- `POST /` — `Action=GetWebIdentityToken`, AWS query protocol in, STS XML out
- `GET /.well-known/jwks.json` — the public keys that verify minted tokens
- `GET /.well-known/openid-configuration` — issuer and JWKS location
- `GET /health`

## Using it

Point your AWS SDK at the stub and your JWT verifier at its key set. Neither
your calling code nor your verifying code needs to change.

```bash
docker run -p 4571:4571 ghcr.io/defra/aws-sts-stub
```

**In the calling service**, redirect the SDK. The access key id becomes the
caller's identity, exactly as real credentials do:

```bash
AWS_ENDPOINT_URL_STS=http://localhost:4571
AWS_REGION=eu-west-2
AWS_ACCESS_KEY_ID=my-frontend      # becomes the token's sub
AWS_SECRET_ACCESS_KEY=stub         # not verified
```

**In the receiving service**, expect this issuer and fetch keys from the stub:

```bash
JWT_ISSUER=https://local.tokens.sts.global.api.aws
JWT_JWKS_URI=http://localhost:4571/.well-known/jwks.json
```

Tokens are minted with `sub` set to
`arn:aws:iam::<AWS_ACCOUNT_ID>:role/<AWS_ACCESS_KEY_ID>`, so a receiver
validating the subject works unchanged.

### Docker Compose

```yaml
services:
  aws-sts-stub:
    image: ghcr.io/defra/aws-sts-stub
    ports:
      - '4571:4571'
    environment:
      AWS_ACCOUNT_ID: '000000000000'
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `4571` | Listen port |
| `AWS_ACCOUNT_ID` | `000000000000` | Account named in the minted `sub` |

Both have defaults, so the stub runs with no configuration.

`DurationSeconds`, a request parameter rather than an environment variable,
defaults to 300 seconds and accepts 60–3600. A harness that assumes a
long-lived token and caches it will flake once the default expiry passes.

The issuer is the fixed constant `https://local.tokens.sts.global.api.aws`. It
is a name rather than an address — nothing fetches it — so it stays the same
however you reach the stub. Copy it into your verifier. Keys are fetched from
the JWKS URL instead, which is why that is the setting that varies between
running on a host and running on a Compose network.

Because the issuer is a name, verifiers that resolve metadata by fetching
`{iss}/.well-known/openid-configuration` from the issuer string itself —
Spring's `JwtDecoders.fromIssuerLocation`, `openid-client`, ASP.NET's OIDC
handler — will fail DNS. Configure those verifiers with the metadata URL
directly instead.

## Fidelity

Everything real STS takes from the request is taken from the request:
`Audience` becomes `aud`, `DurationSeconds` sets the expiry, `SigningAlgorithm`
selects RS256 or ES384, `Tags` become custom claims, and the caller and region
come from the SigV4 credential scope. Requests are validated as the API
documents them and rejections use the query protocol's error shape.

Two deliberate differences:

- **The signing keys are fixed and committed.** Real STS rotates its keys. A
  stub whose `kid` changed on restart would strand its consumers' cached key
  sets. These keys sign test tokens only.
- **SigV4 signatures are not verified.** There are no real credentials to
  verify against. The access key id is read for identity, not checked.

The stub runs on [hapi](https://hapi.dev) and uses
[`jose`](https://github.com/panva/jose) for JWT signing and key handling.

## Compatibility

Verified against `@aws-sdk/client-sts` by the integration suite, which drives
the stub with the real client rather than a recorded fixture. The client's
requests go through hapi's `server.inject`, so no port is opened. If AWS changes
the wire format, the SDK changes with it and `npm run test:integration` fails.

## Development

```bash
npm install                # Node 24
npm run lint               # tsc typecheck of the JSDoc types
npm run test:unit          # stub internals
npm run test:integration   # routes, and conformance against the real AWS SDK
npm test                   # all of the above
npm start
```
