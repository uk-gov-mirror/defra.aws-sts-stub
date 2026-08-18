import { randomUUID } from 'node:crypto'

import { SUPPORTED_ALGORITHMS } from './keys.js'

const XMLNS = 'https://sts.amazonaws.com/doc/2011-06-15/'

const SUPPORTED_ACTION = 'GetWebIdentityToken'
const DEFAULT_DURATION_SECONDS = 300
const MIN_DURATION_SECONDS = 60
const MAX_DURATION_SECONDS = 3600

/**
 * RFC 7519 §4.1 registered claim names. A request tag using one of these as
 * its key would land in the token payload and either overwrite an identity
 * claim (if this object literal were ever reordered) or produce a claim,
 * such as `nbf`, that breaks verification everywhere. Rejecting them at the
 * request boundary keeps that protection true regardless of how the token
 * payload is built.
 */
const RESERVED_CLAIMS = new Set(['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'])

/** An error the stub reports in the query protocol's error shape */
export class StsError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   */
  constructor(code, message) {
    super(message)
    this.name = 'StsError'
    this.code = code
  }
}

/**
 * Collects an indexed query-protocol list, e.g. `Audience.member.1`
 * @param {URLSearchParams} params
 * @param {string} prefix
 * @param {string} [suffix]
 */
function listMembers(params, prefix, suffix = '') {
  const values = []

  for (let index = 1; ; index += 1) {
    const value = params.get(`${prefix}.member.${index}${suffix}`)
    if (value === null) {
      return values
    }
    values.push(value)
  }
}

/**
 * Real STS identifies the caller from the credentials that signed the
 * request. The access key id in the SigV4 credential scope is the equivalent
 * a stub has, and it preserves the property that matters: the caller cannot
 * ask to be someone else.
 * @param {string} [authorization]
 */
function callerFrom(authorization) {
  const scope = /Credential=([^/]+)\/[^/]+\/([^/]+)\//.exec(authorization ?? '')

  if (!scope) {
    throw new StsError(
      'IncompleteSignature',
      'Authorization header requires a Credential parameter'
    )
  }

  return { serviceName: scope[1], region: scope[2] }
}

/**
 * @param {URLSearchParams} params
 */
function durationFrom(params) {
  const raw = params.get('DurationSeconds')

  if (raw === null) {
    return DEFAULT_DURATION_SECONDS
  }

  const seconds = Number(raw)

  if (
    !Number.isInteger(seconds) ||
    seconds < MIN_DURATION_SECONDS ||
    seconds > MAX_DURATION_SECONDS
  ) {
    throw new StsError(
      'ValidationError',
      `DurationSeconds must be between ${MIN_DURATION_SECONDS} and ${MAX_DURATION_SECONDS}`
    )
  }

  return seconds
}

/**
 * Parses a query-protocol request body into the operation's parameters
 * @param {string} body
 * @param {string} [authorization]
 */
export function parseRequest(body, authorization) {
  const params = new URLSearchParams(body)
  const action = params.get('Action')

  if (action !== SUPPORTED_ACTION) {
    throw new StsError(
      'InvalidAction',
      `This stub implements ${SUPPORTED_ACTION} only, not ${action}`
    )
  }

  const algorithm = params.get('SigningAlgorithm')
  const audience = listMembers(params, 'Audience')

  if (algorithm === null || !SUPPORTED_ALGORITHMS.includes(algorithm)) {
    throw new StsError(
      'ValidationError',
      `SigningAlgorithm must be one of ${SUPPORTED_ALGORITHMS.join(', ')}`
    )
  }

  if (audience.length === 0) {
    throw new StsError('ValidationError', 'Audience must have at least 1 member')
  }

  const tagKeys = listMembers(params, 'Tags', '.Key')
  const tagValues = listMembers(params, 'Tags', '.Value')

  const reservedKey = tagKeys.find((key) => RESERVED_CLAIMS.has(key))

  if (reservedKey) {
    throw new StsError(
      'ValidationError',
      `Tag key ${reservedKey} is a reserved claim name and cannot be used`
    )
  }

  return {
    action,
    audience,
    algorithm,
    durationSeconds: durationFrom(params),
    tags: tagKeys.map((Key, index) => ({ Key, Value: tagValues[index] })),
    ...callerFrom(authorization)
  }
}

/**
 * @param {string} value
 */
function escapeXml(value) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

/**
 * The success envelope, matching the `resultWrapper` the service model declares
 * @param {{ token: string, expiresAt: Date }} result
 */
export function successXml({ token, expiresAt }) {
  return `<GetWebIdentityTokenResponse xmlns="${XMLNS}">
  <GetWebIdentityTokenResult>
    <WebIdentityToken>${escapeXml(token)}</WebIdentityToken>
    <Expiration>${expiresAt.toISOString()}</Expiration>
  </GetWebIdentityTokenResult>
  <ResponseMetadata>
    <RequestId>${randomUUID()}</RequestId>
  </ResponseMetadata>
</GetWebIdentityTokenResponse>`
}

/**
 * @param {string} code
 * @param {string} message
 */
export function errorXml(code, message) {
  return `<ErrorResponse xmlns="${XMLNS}">
  <Error>
    <Type>Sender</Type>
    <Code>${escapeXml(code)}</Code>
    <Message>${escapeXml(message)}</Message>
  </Error>
  <RequestId>${randomUUID()}</RequestId>
</ErrorResponse>`
}
