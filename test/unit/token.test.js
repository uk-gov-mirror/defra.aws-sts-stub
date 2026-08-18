import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createLocalJWKSet, jwtVerify } from 'jose'

import { ISSUER, jwks } from '../../src/keys.js'
import { mintToken } from '../../src/token.js'

const keySet = createLocalJWKSet(jwks())

const baseInput = {
  audience: ['some-backend'],
  durationSeconds: 300,
  algorithm: 'RS256',
  serviceName: 'some-frontend',
  region: 'eu-west-2',
  awsAccountId: '000000000000',
  tags: []
}

test('mints a token that verifies against the published key set', async () => {
  const { token } = await mintToken(baseInput)

  const { payload } = await jwtVerify(token, keySet, {
    issuer: ISSUER,
    audience: 'some-backend'
  })

  assert.equal(payload.sub, 'arn:aws:iam::000000000000:role/some-frontend')
})

test('derives the subject from the caller rather than the request', async () => {
  const { token } = await mintToken({
    ...baseInput,
    serviceName: 'other-caller'
  })
  const { payload } = await jwtVerify(token, keySet, { issuer: ISSUER })

  assert.equal(payload.sub, 'arn:aws:iam::000000000000:role/other-caller')
})

test('mints ES384 when asked, verifiable with the ES384 key', async () => {
  const { token } = await mintToken({ ...baseInput, algorithm: 'ES384' })

  const { payload, protectedHeader } = await jwtVerify(token, keySet, {
    issuer: ISSUER
  })

  assert.equal(protectedHeader.alg, 'ES384')
  assert.equal(payload.sub, 'arn:aws:iam::000000000000:role/some-frontend')
})

test('a single audience is a string and several are an array', async () => {
  const decode = (/** @type {string} */ token) =>
    JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString())

  const one = await mintToken(baseInput)
  const many = await mintToken({ ...baseInput, audience: ['a', 'b'] })

  assert.equal(decode(one.token).aud, 'some-backend')
  assert.deepEqual(decode(many.token).aud, ['a', 'b'])
})

test('expiry follows the requested duration', async () => {
  const { token, expiresAt } = await mintToken({
    ...baseInput,
    durationSeconds: 900
  })
  const payload = JSON.parse(
    Buffer.from(token.split('.')[1], 'base64url').toString()
  )

  assert.equal(payload.exp - payload.iat, 900)
  assert.equal(expiresAt.getTime(), payload.exp * 1000)
})

test('carries the AWS claim block describing the caller', async () => {
  const { token } = await mintToken(baseInput)
  const payload = JSON.parse(
    Buffer.from(token.split('.')[1], 'base64url').toString()
  )
  const aws = payload['https://sts.amazonaws.com/']

  assert.equal(aws.aws_account, '000000000000')
  assert.equal(aws.principal_id, 'arn:aws:iam::000000000000:role/some-frontend')
  assert.equal(aws.source_region, 'eu-west-2')
  assert.equal(aws.principal_tags.ServiceName, 'some-frontend')
})

test('request tags become custom claims', async () => {
  const { token } = await mintToken({
    ...baseInput,
    tags: [{ Key: 'Team', Value: 'platform' }]
  })
  const payload = JSON.parse(
    Buffer.from(token.split('.')[1], 'base64url').toString()
  )

  assert.equal(payload.Team, 'platform')
})

test('a caller cannot override identity claims with request tags', async () => {
  const { token } = await mintToken({
    ...baseInput,
    tags: [
      { Key: 'sub', Value: 'arn:aws:iam::000000000000:role/somebody-else' },
      { Key: 'aud', Value: 'another-service' },
      { Key: 'iss', Value: 'https://attacker.example' }
    ]
  })
  const payload = JSON.parse(
    Buffer.from(token.split('.')[1], 'base64url').toString()
  )

  assert.equal(payload.sub, 'arn:aws:iam::000000000000:role/some-frontend')
  assert.equal(payload.aud, 'some-backend')
  assert.equal(payload.iss, ISSUER)
})
