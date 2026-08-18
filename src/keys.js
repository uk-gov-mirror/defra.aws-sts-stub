import { calculateJwkThumbprint, exportJWK, importJWK } from 'jose'

import keyMaterial from './keys.json' with { type: 'json' }

/**
 * The identity this stub mints tokens under. Fixed rather than configurable:
 * consumers reach the stub under different host names, so a host-derived
 * issuer would mint a different `iss` for each caller and none would verify.
 * A consumer copies this string into whatever its verifier compares against.
 */
export const ISSUER = 'https://local.tokens.sts.global.api.aws'

/**
 * The public members of a JWK, with the signing material removed. Dropping
 * `d` is what actually turns this into a public key when it is imported
 * below; the RSA-only fields are dropped alongside it for the same reason,
 * belt and braces. The real guarantee that no private material reaches the
 * published JWKS comes from `importJWK` building a public-only key from
 * this object and `exportJWK` only ever emitting what that key holds, not
 * from this list being complete.
 * @param {JWK} jwk
 * @returns {JWK}
 */
function publicMembersOf({ d, p, q, dp, dq, qi, ...publicJwk }) {
  return publicJwk
}

/**
 * @param {string} alg
 * @param {JWK} jwk
 */
async function buildSigningKey(alg, jwk) {
  const privateKey = await importJWK(jwk, alg)
  const publicKey = await importJWK(publicMembersOf(jwk), alg, {
    extractable: true
  })
  const publicJwk = await exportJWK(publicKey)

  // RFC 7638 thumbprint, so a consumer's cached key set keeps matching across
  // restarts and changes only if the key itself does. Prefixed so a
  // developer reading a JWKS or a token header can see at a glance which key
  // set it came from.
  const kid = `aws-sts-stub-${await calculateJwkThumbprint(publicJwk)}`

  return { alg, kid, privateKey, publicJwk }
}

async function buildSigningKeys() {
  const entries = await Promise.all(
    Object.entries(keyMaterial).map(async ([alg, jwk]) => [
      alg,
      await buildSigningKey(alg, jwk)
    ])
  )

  return Object.fromEntries(entries)
}

/** Signing keys by algorithm, named as the API's `SigningAlgorithm` names them */
export const signingKeys = await buildSigningKeys()

/**
 * The `SigningAlgorithm` values this stub can mint, derived from the keys
 * that actually exist rather than listed by hand, so the two can never
 * disagree.
 */
export const SUPPORTED_ALGORITHMS = Object.keys(signingKeys)

/**
 * The public keys, in the shape a JWKS endpoint serves
 * @returns {{ keys: JWK[] }}
 */
export function jwks() {
  return {
    keys: Object.values(signingKeys).map((key) => ({
      ...key.publicJwk,
      kid: key.kid,
      alg: key.alg,
      use: 'sig'
    }))
  }
}

/**
 * @import { JWK } from 'jose'
 */
