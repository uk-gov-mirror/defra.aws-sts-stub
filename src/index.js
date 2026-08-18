import { createServer } from './server.js'

const port = Number(process.env.PORT ?? 4571)

const server = createServer({ port })

await server.start()
process.stdout.write(`aws-sts-stub listening on ${port}\n`)

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, async () => {
    await server.stop()
    process.exit(0)
  })
}
