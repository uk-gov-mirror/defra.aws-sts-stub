import { test, after, before } from 'node:test'
import assert from 'node:assert/strict'
import {
  GetWebIdentityTokenCommand,
  STSClient,
  STSServiceException
} from '@aws-sdk/client-sts'
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose'

import { ISSUER, jwks } from '../../src/keys.js'
import { createServer } from '../../src/server.js'

const AWS_ACCOUNT_ID = '000000000000'

/** @type {Server} */
let server
/** @type {STSClient} */
let client

before(async () => {
  server = await createServer({
    awsAccountId: AWS_ACCOUNT_ID,
    host: '127.0.0.1',
    logger: { level: 'silent' }
  })
  await server.start()

  client = new STSClient({
    endpoint: server.info.uri,
    region: 'eu-west-2',
    credentials: {
      accessKeyId: 'some-frontend',
      secretAccessKey: 'stub'
    }
  })
})

after(async () => {
  client.destroy()
  await server.stop()
})

/**
 * @param {string} algorithm
 */
const getToken = (algorithm) =>
  client.send(
    new GetWebIdentityTokenCommand({
      SigningAlgorithm: algorithm,
      Audience: ['some-backend'],
      DurationSeconds: 300
    })
  )

test('the real SDK can call the stub and parse its reply', async () => {
  const response = await getToken('RS256')

  // The SDK's deserializer, generated from the service model, is the shape
  // check. decodeJwt throws if it did not hand back a JWT.
  const { exp } = decodeJwt(response.WebIdentityToken ?? '')
  assert.equal(response.Expiration?.getTime(), (exp ?? 0) * 1000)
})

test('the minted token verifies against the published key set', async () => {
  const { WebIdentityToken = '' } = await getToken('RS256')

  const { payload } = await jwtVerify(
    WebIdentityToken,
    createLocalJWKSet(jwks()),
    { issuer: ISSUER, audience: 'some-backend' }
  )

  assert.equal(
    payload.sub,
    `arn:aws:iam::${AWS_ACCOUNT_ID}:role/some-frontend`
  )
})

test('both signing algorithms the API documents are usable', async () => {
  for (const algorithm of ['RS256', 'ES384']) {
    const { WebIdentityToken = '' } = await getToken(algorithm)

    const { protectedHeader } = await jwtVerify(
      WebIdentityToken,
      createLocalJWKSet(jwks()),
      { issuer: ISSUER }
    )

    assert.equal(protectedHeader.alg, algorithm)
  }
})

test('the SDK surfaces a rejected request as a modelled error', async () => {
  await assert.rejects(
    () =>
      client.send(
        new GetWebIdentityTokenCommand({
          SigningAlgorithm: 'RS256',
          Audience: ['some-backend'],
          DurationSeconds: 10
        })
      ),
    (err) => {
      assert.ok(err instanceof STSServiceException)
      assert.equal(err.name, 'ValidationError')
      assert.equal(err.$fault, 'client')
      return true
    }
  )
})

/**
 * @import { Server } from '@hapi/hapi'
 */
