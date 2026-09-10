import { ISSUER, signingKeys } from './keys.js'
import { createServer } from './server.js'

const port = Number(process.env.PORT ?? 4571)
const awsAccountId = process.env.AWS_ACCOUNT_ID ?? '000000000000'
const logLevel = process.env.LOG_LEVEL ?? 'info'
const logFormat = process.env.LOG_FORMAT ?? 'pretty'

const server = await createServer({
  awsAccountId,
  port,
  logger: {
    level: logLevel,
    // Pretty lines rather than JSON by default, so that a developer can read
    // the stub's output in a terminal or `docker compose logs`. The request
    // line already carries the method, path, status and time, and the
    // startup line the port.
    ...(logFormat === 'pretty' && {
      transport: {
        target: 'pino-pretty',
        options: {
          ignore:
            'pid,hostname,req,res,responseTime,created,started,host,protocol,id,uri,address'
        }
      }
    })
  }
})

await server.start()

server.logger.info(
  {
    port,
    awsAccountId,
    issuer: ISSUER,
    keys: Object.values(signingKeys).map(({ alg, kid }) => ({ alg, kid }))
  },
  `aws-sts-stub listening on ${port} for account ${awsAccountId}, issuer ${ISSUER}`
)

for (const signal of ['SIGINT', 'SIGTERM']) {
  // The process exits by itself once the server stops, rather than by
  // process.exit, so that the log transport can write its last lines.
  process.on(signal, () => server.stop())
}
