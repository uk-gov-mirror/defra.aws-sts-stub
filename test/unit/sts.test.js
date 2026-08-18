import { test } from 'node:test'
import assert from 'node:assert/strict'

import { StsError, errorXml, parseRequest, successXml } from '../../src/sts.js'

const authorization =
  'AWS4-HMAC-SHA256 Credential=some-frontend/20260818/eu-west-2/sts/aws4_request, ' +
  'SignedHeaders=host;x-amz-date, Signature=deadbeef'

const body =
  'Action=GetWebIdentityToken&Version=2011-06-15' +
  '&Audience.member.1=some-backend&SigningAlgorithm=RS256&DurationSeconds=300'

test('reads the operation parameters from the form body', () => {
  const parsed = parseRequest(body, authorization)

  assert.equal(parsed.action, 'GetWebIdentityToken')
  assert.deepEqual(parsed.audience, ['some-backend'])
  assert.equal(parsed.algorithm, 'RS256')
  assert.equal(parsed.durationSeconds, 300)
})

test('reads every audience member', () => {
  const parsed = parseRequest(
    'Action=GetWebIdentityToken&Audience.member.1=a&Audience.member.2=b' +
      '&SigningAlgorithm=RS256',
    authorization
  )

  assert.deepEqual(parsed.audience, ['a', 'b'])
})

test('takes the caller and region from the SigV4 credential scope', () => {
  const parsed = parseRequest(body, authorization)

  assert.equal(parsed.serviceName, 'some-frontend')
  assert.equal(parsed.region, 'eu-west-2')
})

test('defaults the duration to five minutes', () => {
  const parsed = parseRequest(
    'Action=GetWebIdentityToken&Audience.member.1=a&SigningAlgorithm=RS256',
    authorization
  )

  assert.equal(parsed.durationSeconds, 300)
})

test('reads request tags', () => {
  const parsed = parseRequest(
    'Action=GetWebIdentityToken&Audience.member.1=a&SigningAlgorithm=RS256' +
      '&Tags.member.1.Key=Team&Tags.member.1.Value=platform',
    authorization
  )

  assert.deepEqual(parsed.tags, [{ Key: 'Team', Value: 'platform' }])
})

test('rejects an unsupported action before any other validation', () => {
  assert.throws(
    () =>
      parseRequest(
        'Action=GetCallerIdentity&SigningAlgorithm=HS256',
        authorization
      ),
    (err) =>
      err instanceof StsError &&
      err.code === 'InvalidAction' &&
      /GetCallerIdentity/.test(err.message) &&
      !/SigningAlgorithm/.test(err.message)
  )
})

test('rejects a tag key that collides with a registered claim name', () => {
  for (const key of ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti']) {
    assert.throws(
      () =>
        parseRequest(
          'Action=GetWebIdentityToken&Audience.member.1=a&SigningAlgorithm=RS256' +
            `&Tags.member.1.Key=${key}&Tags.member.1.Value=x`,
          authorization
        ),
      (err) => err instanceof StsError && err.code === 'ValidationError'
    )
  }
})

test('rejects an unsupported signing algorithm', () => {
  assert.throws(
    () =>
      parseRequest(
        'Action=GetWebIdentityToken&Audience.member.1=a&SigningAlgorithm=HS256',
        authorization
      ),
    (err) => err instanceof StsError && err.code === 'ValidationError'
  )
})

test('rejects a missing audience', () => {
  assert.throws(
    () => parseRequest('Action=GetWebIdentityToken&SigningAlgorithm=RS256', authorization),
    (err) => err instanceof StsError && err.code === 'ValidationError'
  )
})

test('rejects a duration outside the permitted range', () => {
  for (const seconds of [59, 3601]) {
    assert.throws(
      () =>
        parseRequest(
          `Action=GetWebIdentityToken&Audience.member.1=a&SigningAlgorithm=RS256&DurationSeconds=${seconds}`,
          authorization
        ),
      (err) => err instanceof StsError && err.code === 'ValidationError'
    )
  }
})

test('wraps the result the way the service model declares', () => {
  const xml = successXml({
    token: 'a.b.c',
    expiresAt: new Date('2026-08-18T12:00:00Z')
  })

  assert.match(xml, /<GetWebIdentityTokenResponse xmlns=/)
  assert.match(xml, /<GetWebIdentityTokenResult>/)
  assert.match(xml, /<WebIdentityToken>a\.b\.c<\/WebIdentityToken>/)
  assert.match(xml, /<Expiration>2026-08-18T12:00:00\.000Z<\/Expiration>/)
})

test('renders errors in the query protocol shape', () => {
  const xml = errorXml('ValidationError', 'nope')

  assert.match(xml, /<ErrorResponse xmlns=/)
  assert.match(xml, /<Code>ValidationError<\/Code>/)
  assert.match(xml, /<Message>nope<\/Message>/)
})
