import { randomUUID } from 'node:crypto'

import { SignJWT } from 'jose'

import { ISSUER, signingKeys } from './keys.js'

/**
 * Mints a web identity token for a caller.
 *
 * Every value here comes from the request or from the stub's own
 * configuration. Nothing about the token's shape is configurable, because the
 * API it imitates offers no such parameter.
 *
 * Request tags go into the builder alongside the identity claims, and each
 * identity claim is then set through its own builder method, so that method
 * always wins regardless of what a same-named tag put there first.
 * `parseRequest` already rejects a tag key that matches a registered claim
 * name; this is a second, structural guarantee of the same property.
 * @param {{
 *   audience: string[],
 *   durationSeconds: number,
 *   algorithm: string,
 *   serviceName: string,
 *   region: string,
 *   awsAccountId: string,
 *   tags: { Key: string, Value: string }[]
 * }} input
 * @returns {Promise<{ token: string, expiresAt: Date }>}
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
    // A number here is used as-is rather than as an offset from now, so the
    // token's `exp` and the `expiresAt` returned below cannot drift apart.
    .setExpirationTime(expiresAt)
    .setJti(randomUUID())
    .sign(key.privateKey)

  return {
    token,
    expiresAt: new Date(expiresAt * 1000)
  }
}
