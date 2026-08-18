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
 * The discovery document. `jwks_uri` is built from the request Host so it is
 * correct for whichever consumer asked, while `issuer` stays constant.
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
 * Every error leaves as STS XML, so a caller using the AWS SDK gets a
 * modelled error rather than a parse failure.
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
 * Builds the stub's HTTP server
 * @param {{ awsAccountId: string, port?: number }} config
 */
export function createServer({ awsAccountId, port = 0 }) {
  const server = Hapi.server({ port })

  server.ext('onPreResponse', xmlErrors)

  server.route([
    {
      method: 'POST',
      path: '/',
      // The query protocol body is parsed by hand, so take it as-is.
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
