import { test, after, before } from 'node:test'
import assert from 'node:assert/strict'

import { ISSUER, jwks } from '../../src/keys.js'
import { createServer } from '../../src/server.js'

const authorization =
  'AWS4-HMAC-SHA256 Credential=some-frontend/20260818/eu-west-2/sts/aws4_request, ' +
  'SignedHeaders=host;x-amz-date, Signature=deadbeef'

/** @type {Server} */
let server

before(async () => {
  server = createServer({ awsAccountId: '000000000000' })
  await server.initialize()
})

after(() => server.stop())

test('GET /health', async () => {
  const res = await server.inject({ method: 'GET', url: '/health' })

  assert.equal(res.statusCode, 200)
  assert.match(res.headers['content-type'] ?? '', /^application\/json/)
  assert.deepEqual(res.result, { message: 'success' })
})

test('GET /.well-known/jwks.json serves the public key set', async () => {
  const res = await server.inject({ method: 'GET', url: '/.well-known/jwks.json' })

  assert.equal(res.statusCode, 200)
  assert.deepEqual(res.result, jwks())
})

test('GET /.well-known/openid-configuration builds jwks_uri from the Host', async () => {
  const res = await server.inject({
    method: 'GET',
    url: '/.well-known/openid-configuration',
    headers: { host: 'sts.local:4571' }
  })

  assert.equal(res.statusCode, 200)
  assert.deepEqual(res.result, {
    issuer: ISSUER,
    jwks_uri: 'http://sts.local:4571/.well-known/jwks.json',
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'jti'],
    id_token_signing_alg_values_supported: ['RS256', 'ES384'],
    subject_types_supported: ['public']
  })
})

test('POST / mints a token', async () => {
  const res = await server.inject({
    method: 'POST',
    url: '/',
    headers: { authorization, 'content-type': 'application/x-www-form-urlencoded' },
    payload:
      'Action=GetWebIdentityToken&Audience.member.1=a&SigningAlgorithm=RS256'
  })

  assert.equal(res.statusCode, 200)
  assert.match(res.headers['content-type'] ?? '', /^text\/xml/)
  assert.match(res.payload, /<WebIdentityToken>[\w-]+\.[\w-]+\.[\w-]+<\/WebIdentityToken>/)
})

test('POST / reports a bad request in the query protocol error shape', async () => {
  const res = await server.inject({
    method: 'POST',
    url: '/',
    headers: { authorization },
    payload: 'Action=GetCallerIdentity'
  })

  assert.equal(res.statusCode, 400)
  assert.match(res.headers['content-type'] ?? '', /^text\/xml/)
  assert.match(res.payload, /<Code>InvalidAction<\/Code>/)
})

test('an unknown route is an UnknownOperation error in XML', async () => {
  const res = await server.inject({ method: 'GET', url: '/nope' })

  assert.equal(res.statusCode, 404)
  assert.match(res.headers['content-type'] ?? '', /^text\/xml/)
  assert.match(res.payload, /<Code>UnknownOperation<\/Code>/)
  assert.match(res.payload, /<Message>No such route: GET \/nope<\/Message>/)
})

/**
 * @import { Server } from '@hapi/hapi'
 */
