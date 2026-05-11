import Fastify from 'fastify'
import fastifyStatic from '@fastify/static'
import fastifyMultipart from '@fastify/multipart'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'
import { runMigrations } from './db.js'
import registerRoutes from './routes/register.js'
import stationsRoutes from './routes/stations.js'
import statusRoutes from './routes/status.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const PORT = parseInt(process.env.PORT || '8080')

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    transport: process.env.NODE_ENV !== 'production'
      ? { target: 'pino-pretty' }
      : undefined,
  },
  ajv: { customOptions: { allErrors: true } },
})

// Static assets (CSS, JS) served from /service/static/
await app.register(fastifyStatic, {
  root: join(__dirname, '../public'),
  prefix: '/service/static/',
  decorateReply: false,
})

// Multipart for logo uploads (5 MB max)
await app.register(fastifyMultipart, {
  limits: { fileSize: 5 * 1024 * 1024 },
})

// Routes
await app.register(registerRoutes)
await app.register(stationsRoutes)
await app.register(statusRoutes)

// Serve the SPA for all /service* GET requests not matched above
app.get('/service', serveUI)
app.get('/service/', serveUI)

app.setNotFoundHandler(async (req, reply) => {
  if (req.method === 'GET' && req.url.startsWith('/service')) {
    return serveUI(req, reply)
  }
  return reply.status(404).send({ error: 'Not found' })
})

async function serveUI(_req, reply) {
  return reply.sendFile('index.html', join(__dirname, '../public'))
}

// Health
app.get('/healthz', async () => ({ status: 'ok', service: 'radio-service' }))

// Run migrations, then start
await runMigrations()
await app.listen({ port: PORT, host: '0.0.0.0' })
console.log(`[radio-service] listening on :${PORT}`)
