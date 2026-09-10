import { randomUUID } from 'node:crypto'

import { SignJWT } from 'jose'

import { ISSUER, signingKeys } from './keys.js'

/**
 * Tags go in first. Each identity claim is then set by its own builder
 * method, so a same-named tag can never win.
 * @param {{
 *   audience: string[],
 *   durationSeconds: number,
 *   algorithm: string,
 *   serviceName: string,
 *   region: string,
 *   awsAccountId: string,
 *   tags: { Key: string, Value: string }[]
 * }} input
 * @returns {Promise<{
 *   token: string,
 *   expiresAt: Date,
 *   principal: string,
 *   kid: string,
 *   jti: string
 * }>}
 */
export async function mintToken({
  audience,
  durationSeconds,
  algorithm,
  serviceName,
  region,
  awsAccountId,
  tags
}) {
  const key = signingKeys[algorithm]
  const issuedAt = Math.floor(Date.now() / 1000)
  const expiresAt = issuedAt + durationSeconds
  const principal = `arn:aws:iam::${awsAccountId}:role/${serviceName}`
  const jti = randomUUID()

  const token = await new SignJWT({
    ...Object.fromEntries(tags.map(({ Key, Value }) => [Key, Value])),
    'https://sts.amazonaws.com/': {
      aws_account: awsAccountId,
      principal_id: principal,
      source_region: region,
      principal_tags: { ServiceName: serviceName }
    }
  })
    .setProtectedHeader({ alg: key.alg, typ: 'JWT', kid: key.kid })
    .setSubject(principal)
    .setAudience(audience.length === 1 ? audience[0] : audience)
    .setIssuer(ISSUER)
    .setIssuedAt(issuedAt)
    // A number is used as-is, so `exp` matches `expiresAt` below.
    .setExpirationTime(expiresAt)
    .setJti(jti)
    .sign(key.privateKey)

  return {
    token,
    expiresAt: new Date(expiresAt * 1000),
    principal,
    kid: key.kid,
    jti
  }
}
