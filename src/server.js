import Hapi from '@hapi/hapi'

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
    return xml(h, 404, errorXml('UnknownOperation', `No such route: ${route}`))
  }

  return xml(h, statusCode, errorXml('InternalFailure', String(response)))
}

/**
 * @param {{ awsAccountId: string, port?: number, host?: string }} config
 */
export function createServer({ awsAccountId, port = 0, host }) {
  const server = Hapi.server({ port, host })

  server.ext('onPreResponse', xmlErrors)

  server.route([
    {
      method: 'POST',
      path: '/',
      options: { payload: { parse: false } },
      handler: async (request, h) => {
        try {
          const parsed = parseRequest(
            String(request.payload ?? ''),
            /** @type {string | undefined} */ (request.headers.authorization)
          )
          const token = await mintToken({ ...parsed, awsAccountId })

          return xml(h, 200, successXml(token))
        } catch (err) {
          if (err instanceof StsError) {
            return xml(h, 400, errorXml(err.code, err.message))
          }
          throw err
        }
      }
    },
    {
      method: 'GET',
      path: '/health',
      handler: () => ({ message: 'success' })
    },
    {
      method: 'GET',
      path: '/.well-known/jwks.json',
      handler: () => jwks()
    },
    {
      method: 'GET',
      path: '/.well-known/openid-configuration',
      handler: (request) => discovery(request)
    }
  ])

  return server
}

/**
 * @import { Lifecycle, Request, ResponseToolkit } from '@hapi/hapi'
 */
