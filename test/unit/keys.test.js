import { test } from 'node:test'
import assert from 'node:assert/strict'

import { ISSUER, jwks, signingKeys } from '../../src/keys.js'

test('publishes one public key per supported algorithm', () => {
  const { keys } = jwks()

  assert.equal(keys.length, 2)
  assert.deepEqual(
    keys.map((key) => key.alg).sort(),
    ['ES384', 'RS256']
  )
})

test('every published key carries a kid, a use and no private material', () => {
  for (const key of jwks().keys) {
    assert.ok(key.kid, 'expected a kid')
    assert.equal(key.use, 'sig')
    assert.equal(key.d, undefined, 'private material must not be published')
  }
})

test('published kids match the signing keys', () => {
  const published = jwks()
    .keys.map((key) => key.kid)
    .sort()
  const signing = Object.values(signingKeys)
    .map((key) => key.kid)
    .sort()

  assert.deepEqual(published, signing)
})

test('the issuer is the documented constant', () => {
  assert.equal(ISSUER, 'https://local.tokens.sts.global.api.aws')
})
