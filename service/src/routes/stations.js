import { query } from '../db.js'
import * as pdns from '../pdns.js'

const ADMIN_KEY = process.env.ADMIN_KEY || ''

function checkAdmin(req) {
  if (!ADMIN_KEY) return null
  const key = req.headers['x-admin-key'] || req.body?.admin_key || ''
  return key === ADMIN_KEY ? null : 'Invalid admin key'
}

export default async function stationsRoutes(fastify) {
  fastify.get('/service/stations', async (req) => {
    const limit  = Math.min(parseInt(req.query.limit  || '200'), 1000)
    const offset = Math.max(parseInt(req.query.offset || '0'), 0)
    const res = await query(`
      SELECT s.*, p.dns_provisioned, p.si_published, p.dns_valid, p.srv_valid,
             p.si_reachable, p.stream_reachable, p.last_validated
      FROM stations s
      LEFT JOIN provisioning_status p ON p.station_id = s.id
      ORDER BY s.created_at DESC
      LIMIT $1 OFFSET $2
    `, [limit, offset])
    const total = (await query('SELECT COUNT(*) FROM stations')).rows[0].count
    return { total: parseInt(total), limit, offset, stations: res.rows }
  })

  fastify.get('/service/stations/:id', async (req, reply) => {
    const res = await query(`
      SELECT s.*, p.dns_provisioned, p.si_published, p.dns_valid, p.srv_valid,
             p.si_reachable, p.stream_reachable, p.last_validated, p.provision_log
      FROM stations s
      LEFT JOIN provisioning_status p ON p.station_id = s.id
      WHERE s.id = $1
    `, [req.params.id])
    if (!res.rows.length) return reply.status(404).send({ error: 'Station not found' })
    return res.rows[0]
  })

  fastify.delete('/service/stations/:id', async (req, reply) => {
    const authErr = checkAdmin(req)
    if (authErr) return reply.status(403).send({ error: authErr })

    const res = await query('SELECT * FROM stations WHERE id=$1', [req.params.id])
    if (!res.rows.length) return reply.status(404).send({ error: 'Station not found' })
    const station = res.rows[0]

    const warnings = []
    for (const name of [
      station.fqdn,
      `_radioepg._tcp.${station.svc_fqdn}`,
      `_radiospi._tcp.${station.svc_fqdn}`,
    ]) {
      const type = name.startsWith('_') ? 'SRV' : 'CNAME'
      try { await pdns.deleteRRSet(name, type) } catch (e) { warnings.push(`${name}: ${e.message}`) }
    }

    await query('DELETE FROM stations WHERE id=$1', [station.id])
    return { ok: true, deleted: station.id, fqdn: station.fqdn, warnings }
  })

  // PowerDNS connectivity probe
  fastify.get('/service/pdns-status', async () => pdns.getStatus())
}
