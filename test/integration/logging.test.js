import { test, after, before, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { Writable } from 'node:stream'

import { signingKeys } from '../../src/keys.js'
import { createServer } from '../../src/server.js'

const authorization =
  'AWS4-HMAC-SHA256 Credential=some-frontend/20260818/eu-west-2/sts/aws4_request, ' +
  'SignedHeaders=host;x-amz-date, Signature=deadbeef'

/** @type {Record<string, any>[]} */
let lines = []

const stream = new Writable({
  write(chunk, _encoding, callback) {
    lines.push(JSON.parse(String(chunk)))
    callback()
  }
})

/** @type {Server} */
let server

before(async () => {
  server = await createServer({
    awsAccountId: '000000000000',
    logger: {
      stream: /** @type {NodeJS.WriteStream} */ (/** @type {unknown} */ (stream))
    }
  })
  server.route({
    method: 'GET',
    path: '/throws',
    handler: () => {
      throw new Error('Something broke')
    }
  })
  await server.initialize()
})

beforeEach(() => {
  lines = []
})

after(() => server.stop())

/**
 * @param {string} msg
 */
const logged = (msg) => lines.find((line) => line.msg?.startsWith(msg))

test('a minted token is logged with the identity it names', async () => {
  const res = await server.inject({
    method: 'POST',
    url: '/',
    headers: { authorization },
    payload:
      'Action=GetWebIdentityToken&Audience.member.1=some-backend' +
      '&SigningAlgorithm=ES384&DurationSeconds=900' +
      '&Tags.member.1.Key=Team&Tags.member.1.Value=platform'
  })
  const token = /<WebIdentityToken>(.+)<\/WebIdentityToken>/.exec(res.payload)?.[1]

  const minted = logged('Minted ES384 token')

  assert.equal(
    minted?.msg,
    'Minted ES384 token for arn:aws:iam::000000000000:role/some-frontend, audience some-backend'
  )
  assert.equal(minted?.level, 30)
  assert.deepEqual(
    { ...minted?.sts, jti: undefined, expiresAt: undefined },
    {
      caller: 'some-frontend',
      sub: 'arn:aws:iam::000000000000:role/some-frontend',
      region: 'eu-west-2',
      audience: ['some-backend'],
      algorithm: 'ES384',
      kid: signingKeys.ES384.kid,
      jti: undefined,
      durationSeconds: 900,
      expiresAt: undefined,
      tags: { Team: 'platform' }
    }
  )
  assert.equal(logged('Minted token')?.token, token)
})

test('a rejected request is logged with the STS error code', async () => {
  await server.inject({
    method: 'POST',
    url: '/',
    headers: { authorization },
    payload: 'Action=GetCallerIdentity'
  })

  const rejected = logged('Rejected STS request')

  assert.equal(
    rejected?.msg,
    'Rejected STS request: InvalidAction: This stub implements GetWebIdentityToken only, not GetCallerIdentity'
  )
  assert.equal(rejected?.level, 40)
})

test('an unknown route is logged as a warning', async () => {
  await server.inject({ method: 'POST', url: '/sts' })

  assert.equal(logged('No such route')?.msg, 'No such route: POST /sts')
})

test('an unhandled error is logged with its stack', async () => {
  await server.inject({ method: 'GET', url: '/throws' })

  const failure = lines.find((line) => line.level === 50)

  assert.match(failure?.err?.stack ?? '', /Error: Something broke/)
})

test('health checks are not logged', async () => {
  await server.inject({ method: 'GET', url: '/health' })

  assert.deepEqual(lines, [])
})

/**
 * @import { Server } from '@hapi/hapi'
 */
