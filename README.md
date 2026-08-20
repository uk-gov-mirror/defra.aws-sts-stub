# aws-sts-stub

A local stand-in for the AWS STS [`GetWebIdentityToken`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetWebIdentityToken.html)
API. Services that authenticate to each other with AWS Web Identity tokens
can run locally and in test harnesses without AWS.

For local development and testing only. The signing keys are committed and
public, so anyone can mint a token for any identity.

## Why use it

This is a dumb stub. It checks that a request has the shape the API documents,
then mints a token for whatever identity the caller names. It doesn't verify any 
anything security related (e.g. the SigV4 signature, the secret key, that the caller
exists).

This is intentional, for testing. Your service keeps the real AWS SDK and the real token
flow in tests, with no second code path that swaps AWS out. Set
`AWS_ENDPOINT_URL_STS` to the stub's address and the SDK sends its STS calls
there. No code changes; one environment variable does.

## Endpoints

- `POST /` — `Action=GetWebIdentityToken`. AWS query protocol in, STS XML out
- `GET /.well-known/jwks.json` — the public keys that verify minted tokens
- `GET /.well-known/openid-configuration` — issuer and JWKS location
- `GET /health`

## Use

```bash
docker run -p 4571:4571 ghcr.io/defra/aws-sts-stub
```

In the calling service, point the AWS SDK at the stub. The access key id is
the caller's identity:

```bash
AWS_ENDPOINT_URL_STS=http://localhost:4571
AWS_REGION=eu-west-2
AWS_ACCESS_KEY_ID=my-frontend      # becomes the token's sub
AWS_SECRET_ACCESS_KEY=stub         # not verified
```

In the receiving service, use this issuer and fetch keys from the stub:

```bash
JWT_ISSUER=https://local.tokens.sts.global.api.aws
JWT_JWKS_URI=http://localhost:4571/.well-known/jwks.json
```

`sub` is `arn:aws:iam::<AWS_ACCOUNT_ID>:role/<AWS_ACCESS_KEY_ID>`.

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

| Variable         | Default        | Purpose                         |
| ---------------- | -------------- | ------------------------------- |
| `PORT`           | `4571`         | Listen port                     |
| `AWS_ACCOUNT_ID` | `000000000000` | Account named in the minted `sub` |

`DurationSeconds` is a request parameter. It defaults to 300 and accepts
60–3600.

The issuer is the fixed name `https://local.tokens.sts.global.api.aws`. It is
not a URL that the stub serves, so it is the same on a host and on a Compose
network. Only the JWKS URL changes between the two.

Verifiers that fetch `{iss}/.well-known/openid-configuration` from the issuer
string, such as `openid-client`, will fail DNS. Give them the metadata URL
directly.

## Fidelity

The token is built from the request, as in real STS. `Audience` becomes
`aud`, `DurationSeconds` sets the expiry, `SigningAlgorithm` selects RS256 or
ES384, `Tags` become custom claims, and the caller and region come from the
SigV4 credential scope. Invalid requests are rejected in the query protocol's
error shape.

Two differences from real STS:

- The signing keys are fixed and committed, so `kid` does not change between
  restarts and cached key sets stay valid.
- SigV4 signatures are not verified. The access key id is read, not checked.

## Compatibility

The integration suite drives the stub with `@aws-sdk/client-sts`. If AWS
changes the wire format, the SDK changes with it and `npm run
test:integration` fails.

## Development

Node 24.

```bash
npm install
npm run lint               # tsc typecheck of the JSDoc types
npm run test:unit
npm run test:integration
npm test                   # all of the above
npm start
```

Built on [hapi](https://hapi.dev); [`jose`](https://github.com/panva/jose)
signs the tokens.
