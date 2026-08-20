import { calculateJwkThumbprint, exportJWK, importJWK } from 'jose'

import keyMaterial from './keys.json' with { type: 'json' }

/**
 * Fixed, not host-derived, so `iss` is the same for every caller.
 */
export const ISSUER = 'https://local.tokens.sts.global.api.aws'

/**
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

  // RFC 7638 thumbprint: stable across restarts, changes only with the key.
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

/** Signing keys by `SigningAlgorithm` name */
export const signingKeys = await buildSigningKeys()

export const SUPPORTED_ALGORITHMS = Object.keys(signingKeys)

/**
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
