import Hapi from '@hapi/hapi'

import { ISSUER, SUPPORTED_ALGORITHMS, jwks } from './keys.js'

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
 * Builds the stub's HTTP server
 * @param {{ port?: number }} config
 */
export function createServer({ port = 0 }) {
  const server = Hapi.server({ port })

  server.route([
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
 * @import { Request } from '@hapi/hapi'
 */
