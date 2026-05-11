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
  logger: { level: process.env.LOG_LEVEL || 'info' },
  ajv: { customOptions: { allErrors: true } },
})

// Health check — registered first so DO App Platform can reach it
// even before the DB finishes connecting.
app.get('/healthz', async () => ({ status: 'ok', service: 'radio-service' }))

// Static assets served from /service/static/
await app.register(fastifyStatic, {
  root: join(__dirname, '../public'),
  prefix: '/service/static/',
})

// Multipart for logo uploads (5 MB max)
await app.register(fastifyMultipart, {
  limits: { fileSize: 5 * 1024 * 1024 },
})

// API routes
await app.register(registerRoutes)
await app.register(stationsRoutes)
await app.register(statusRoutes)

// Serve the SPA for /service and /service/*
app.get('/service', serveUI)
app.get('/service/', serveUI)

app.setNotFoundHandler(async (req, reply) => {
  if (req.method === 'GET' && req.url.startsWith('/service')) {
    return serveUI(req, reply)
  }
  return reply.status(404).send({ error: 'Not found' })
})

function serveUI(_req, reply) {
  return reply.sendFile('index.html')
}

// Start listening immediately so health checks pass, then run migrations.
await app.listen({ port: PORT, host: '0.0.0.0' })
console.log(`[radio-service] listening on :${PORT}`)

// Retry migrations — the DB may still be provisioning on first deploy.
async function migrateWithRetry(attempts = 8, delayMs = 5_000) {
  for (let i = 1; i <= attempts; i++) {
    try {
      await runMigrations()
      console.log('[radio-service] migrations applied')
      return
    } catch (e) {
      console.error(`[radio-service] migration attempt ${i}/${attempts} failed: ${e.message}`)
      if (i < attempts) await new Promise(r => setTimeout(r, delayMs * i))
    }
  }
  console.error('[radio-service] migrations failed after all retries — DB requests will error until resolved')
}

migrateWithRetry()
