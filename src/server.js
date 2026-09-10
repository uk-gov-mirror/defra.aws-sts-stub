import Hapi from '@hapi/hapi'
import hapiPino from 'hapi-pino'

import { ISSUER, SUPPORTED_ALGORITHMS, jwks } from './keys.js'
import { StsError, errorXml, parseRequest, successXml } from './sts.js'
import { mintToken } from './token.js'

const XML = 'text/xml'

/**
 * @param {ResponseToolkit} h
 * @param {number} statusCode
 * @param {string} xml
 */
const xml = (h, statusCode, xml) => h.response(xml).code(statusCode).type(XML)

/**
 * `jwks_uri` follows the request Host; `issuer` is constant.
 * @param {Request} request
 */
function discovery(request) {
  return {
    issuer: ISSUER,
    jwks_uri: `http://${request.info.host}/.well-known/jwks.json`,
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'jti'],
    id_token_signing_alg_values_supported: SUPPORTED_ALGORITHMS,
    subject_types_supported: ['public']
  }
}

/**
 * Sends hapi's own errors as STS XML, so the AWS SDK can parse them.
 * @type {Lifecycle.Method}
 */
function xmlErrors(request, h) {
  const { response } = request

  if (!('isBoom' in response)) {
    return h.continue
  }

  const { statusCode } = response.output

  if (statusCode === 404) {
    const route = `${request.method.toUpperCase()} ${request.path}`

    // A caller that reaches this has the wrong endpoint URL for the stub.
    request.logger.warn(`No such route: ${route}`)

    return xml(h, 404, errorXml('UnknownOperation', `No such route: ${route}`))
  }

  // The XML reply carries only the message, so the stack goes to the log.
  request.logger[statusCode >= 500 ? 'error' : 'warn'](
    { err: response },
    response.message
  )

  return xml(h, statusCode, errorXml('InternalFailure', String(response)))
}

/**
 * @param {Request} request
 * @param {ResponseToolkit} h
 * @param {string} awsAccountId
 */
async function getWebIdentityToken(request, h, awsAccountId) {
  const body = String(request.payload ?? '')

  request.logger.info({ body }, 'STS request body')

  try {
    const parsed = parseRequest(
      body,
      /** @type {string | undefined} */ (request.headers.authorization)
    )
    const minted = await mintToken({ ...parsed, awsAccountId })

    request.logger.info(
      {
        sts: {
          caller: parsed.serviceName,
          sub: minted.principal,
          region: parsed.region,
          audience: parsed.audience,
          algorithm: parsed.algorithm,
          kid: minted.kid,
          jti: minted.jti,
          durationSeconds: parsed.durationSeconds,
          expiresAt: minted.expiresAt.toISOString(),
          tags: Object.fromEntries(
            parsed.tags.map(({ Key, Value }) => [Key, Value])
          )
        }
      },
      `Minted ${parsed.algorithm} token for ${minted.principal}, audience ${parsed.audience.join(', ')}`
    )
    // The full token is for pasting into a JWT decoder when debugging a verifier.
    request.logger.info({ token: minted.token }, 'Minted token')

    return xml(h, 200, successXml(minted))
  } catch (err) {
    if (err instanceof StsError) {
      request.logger.warn(
        { sts: { code: err.code } },
        `Rejected STS request: ${err.code}: ${err.message}`
      )
      return xml(h, 400, errorXml(err.code, err.message))
    }
    throw err
  }
}

/**
 * @param {{
 *   awsAccountId: string,
 *   port?: number,
 *   host?: string,
 *   logger?: Options
 * }} config
 */
export async function createServer({ awsAccountId, port = 0, host, logger }) {
  const server = Hapi.server({ port, host })

  await server.register({
    plugin: hapiPino,
    options: {
      level: 'info',
      // The container health check calls /health every 10 seconds.
      ignorePaths: ['/health'],
      customRequestCompleteMessage: (request, responseTime) =>
        `${request.method.toUpperCase()} ${request.path} ${request.raw.res.statusCode} (${responseTime}ms)`,
      ...logger
    }
  })

  server.ext('onPreResponse', xmlErrors)

  server.route([
    {
      method: 'POST',
      path: '/',
      options: { payload: { parse: false } },
      handler: (request, h) => getWebIdentityToken(request, h, awsAccountId)
    },
    {
      method: 'GET',
      path: '/health',
      handler: () => ({ message: 'success' })
    },
    {
      method: 'GET',
      path: '/.well-known/jwks.json',
      handler: (request) => {
        const keySet = jwks()

        request.logger.info(
          { kids: keySet.keys.map(({ kid }) => kid) },
          'Served JWKS'
        )

        return keySet
      }
    },
    {
      method: 'GET',
      path: '/.well-known/openid-configuration',
      handler: (request) => {
        const metadata = discovery(request)

        // jwks_uri follows the Host header, so it is logged to show which
        // address a verifier was told to fetch keys from.
        request.logger.info(
          { jwksUri: metadata.jwks_uri },
          'Served OpenID configuration'
        )

        return metadata
      }
    }
  ])

  return server
}

/**
 * @import { Lifecycle, Request, ResponseToolkit } from '@hapi/hapi'
 * @import { Options } from 'hapi-pino'
 */
