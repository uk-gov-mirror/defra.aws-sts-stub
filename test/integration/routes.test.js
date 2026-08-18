import { test, after, before } from 'node:test'
import assert from 'node:assert/strict'

import { ISSUER, jwks } from '../../src/keys.js'
import { createServer } from '../../src/server.js'

/** @type {Server} */
let server

before(async () => {
  server = createServer({})
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

/**
 * @import { Server } from '@hapi/hapi'
 */
