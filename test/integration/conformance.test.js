import { test, after, before } from 'node:test'
import assert from 'node:assert/strict'
import { Readable } from 'node:stream'

import {
  GetWebIdentityTokenCommand,
  STSClient,
  STSServiceException
} from '@aws-sdk/client-sts'
import { HttpResponse } from '@smithy/protocol-http'
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose'

import { ISSUER, jwks } from '../../src/keys.js'
import { createServer } from '../../src/server.js'

const AWS_ACCOUNT_ID = '000000000000'

/** @type {Server} */
let server
/** @type {STSClient} */
let client

before(async () => {
  server = createServer({ awsAccountId: AWS_ACCOUNT_ID })
  await server.initialize()

  client = new STSClient({
    endpoint: 'http://sts.local',
    region: 'eu-west-2',
    credentials: {
      accessKeyId: 'some-frontend',
      secretAccessKey: 'stub'
    },
    // The real SDK, but its requests go through server.inject, not a socket
    requestHandler: {
      handle: async (/** @type {HttpRequest} */ req) => {
        const res = await server.inject({
          method: req.method,
          url: req.path,
          headers: req.headers,
          payload: req.body
        })

        return {
          response: new HttpResponse({
            statusCode: res.statusCode,
            headers: /** @type {Record<string, string>} */ (res.headers),
            body: Readable.from([res.rawPayload])
          })
        }
      }
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

  assert.equal(typeof response.WebIdentityToken, 'string')
  assert.equal(response.WebIdentityToken?.split('.').length, 3)

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
    (/** @type {STSServiceException} */ err) => {
      assert.equal(err.$metadata?.httpStatusCode, 400)
      assert.match(err.message, /DurationSeconds/)
      return true
    }
  )
})

/**
 * @import { Server } from '@hapi/hapi'
 * @import { HttpRequest } from '@smithy/protocol-http'
 */
