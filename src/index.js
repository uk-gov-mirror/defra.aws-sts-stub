import { createServer } from './server.js'

const port = Number(process.env.PORT ?? 4571)
const awsAccountId = process.env.AWS_ACCOUNT_ID ?? '000000000000'

const server = createServer({ awsAccountId, port })

await server.start()
process.stdout.write(
  `aws-sts-stub listening on ${port} for account ${awsAccountId}\n`
)

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    await server.stop()
    process.exit(0)
  })
}
