import { query } from '../db.js'
import { normalizePI, normalizeECC, toFreq5, buildFQDN, buildSvcFQDN, getEPGHost } from '../fqdn.js'
import * as pdns from '../pdns.js'
import * as spaces from '../spaces.js'
import { generateSI } from '../spi.js'
import { validate } from '../validator.js'

const ADMIN_KEY = process.env.ADMIN_KEY || ''
const EPG_PORT = parseInt(process.env.EPG_PORT || '80')

function checkAdmin(req) {
  if (!ADMIN_KEY) return null
  const key = req.headers['x-admin-key'] || req.body?.admin_key || ''
  return key === ADMIN_KEY ? null : 'Invalid admin key'
}

export default async function registerRoutes(fastify) {
  // Config endpoint — tells the UI the zone, EPG host, etc.
  fastify.get('/service/config', async () => ({
    zone: process.env.PDNS_ZONE || 'radiodns.zerotrustradio.org',
    epgHost: getEPGHost(),
    adminKeyRequired: Boolean(ADMIN_KEY),
    spacesConfigured: spaces.isConfigured(),
  }))

  fastify.post('/service/register', {
    schema: {
      body: {
        type: 'object',
        required: ['callsign', 'frequency', 'pi', 'ecc', 'contact_email'],
        properties: {
          admin_key:     { type: 'string' },
          callsign:      { type: 'string', minLength: 1, maxLength: 20 },
          frequency:     { type: 'string' },
          pi:            { type: 'string' },
          ecc:           { type: 'string' },
          contact_email: { type: 'string', format: 'email' },
          stream_url:    { type: 'string' },
          website_url:   { type: 'string' },
          country:       { type: 'string', maxLength: 4 },
          service_type:  { type: 'string', enum: ['FM', 'AM', 'HD', 'DAB'] },
          notes:         { type: 'string', maxLength: 500 },
        },
      },
    },
  }, async (req, reply) => {
    const authErr = checkAdmin(req)
    if (authErr) return reply.status(403).send({ error: authErr })

    const { callsign, frequency, pi: piRaw, ecc: eccRaw, contact_email,
            stream_url, website_url, country, notes } = req.body
    const service_type = req.body.service_type || 'FM'

    // Validate and normalise RDS parameters
    let pi, ecc, freq5
    try {
      pi = normalizePI(piRaw)
      ecc = normalizeECC(eccRaw)
      freq5 = toFreq5(frequency)
    } catch (e) {
      return reply.status(400).send({ error: e.message })
    }

    const fqdn     = buildFQDN(freq5, pi, ecc)
    const svcFQDN  = buildSvcFQDN(callsign)
    const epgHost  = getEPGHost()
    const log      = []

    // Upsert station record
    let station
    try {
      const res = await query(`
        INSERT INTO stations
          (callsign, frequency, pi, ecc, freq5, fqdn, svc_fqdn,
           stream_url, website_url, country, service_type, contact_email, notes)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
        ON CONFLICT (fqdn) DO UPDATE SET
          callsign=EXCLUDED.callsign, stream_url=EXCLUDED.stream_url,
          website_url=EXCLUDED.website_url, country=EXCLUDED.country,
          service_type=EXCLUDED.service_type, contact_email=EXCLUDED.contact_email,
          notes=EXCLUDED.notes, updated_at=NOW()
        RETURNING *
      `, [callsign, frequency, pi, ecc, freq5, fqdn, svcFQDN,
          stream_url || null, website_url || null, country || null,
          service_type, contact_email, notes || null])
      station = res.rows[0]
    } catch (e) {
      return reply.status(500).send({ error: `Database error: ${e.message}` })
    }

    let dnsOk = false
    let siUrl = null

    // --- DNS provisioning ---
    try {
      await pdns.upsertCNAME(fqdn, svcFQDN)
      log.push({ step: 'cname', ok: true, record: `${fqdn} → ${svcFQDN}` })

      const epgSRVName = `_radioepg._tcp.${svcFQDN}`
      const spiSRVName = `_radiospi._tcp.${svcFQDN}`
      await pdns.upsertSRV(epgSRVName, 10, 0, EPG_PORT, epgHost)
      await pdns.upsertSRV(spiSRVName, 10, 0, EPG_PORT, epgHost)

      // Store service records
      await query(`DELETE FROM service_records WHERE station_id=$1`, [station.id])
      for (const [srvType, name] of [[epgSRVName, '_radioepg._tcp'], [spiSRVName, '_radiospi._tcp']]) {
        await query(`
          INSERT INTO service_records (station_id, srv_type, target, port, priority, weight)
          VALUES ($1,$2,$3,$4,10,0)
        `, [station.id, name, epgHost, EPG_PORT])
      }

      dnsOk = true
      log.push({ step: 'srv', ok: true, records: [`_radioepg._tcp.${svcFQDN}`, `_radiospi._tcp.${svcFQDN}`] })
    } catch (e) {
      log.push({ step: 'dns', ok: false, error: e.message })
    }

    // --- SI.xml generation + upload ---
    const xml = generateSI(station)
    if (spaces.isConfigured()) {
      try {
        siUrl = await spaces.uploadSI(station.id, xml)
        log.push({ step: 'si_xml', ok: true, url: siUrl })
      } catch (e) {
        log.push({ step: 'si_xml', ok: false, error: e.message })
      }
    } else {
      log.push({ step: 'si_xml', ok: false, error: 'DO Spaces not configured' })
    }

    // --- Persist provisioning status ---
    await query(`
      INSERT INTO provisioning_status (station_id, dns_provisioned, si_published, provision_log)
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (station_id) DO UPDATE SET
        dns_provisioned=$2, si_published=$3, provision_log=$4, updated_at=NOW()
    `, [station.id, dnsOk, Boolean(siUrl), JSON.stringify(log)])

    // --- Background validation (non-blocking) ---
    setImmediate(() => runValidation(station, siUrl))

    return {
      ok: true,
      id: station.id,
      callsign: station.callsign,
      fqdn,
      svc_fqdn: svcFQDN,
      si_url: siUrl,
      provisioning: { dns: dnsOk, si: Boolean(siUrl), log },
    }
  })

  // Logo upload
  fastify.post('/service/stations/:id/logo', async (req, reply) => {
    const authErr = checkAdmin(req)
    if (authErr) return reply.status(403).send({ error: authErr })

    if (!spaces.isConfigured()) {
      return reply.status(503).send({ error: 'Storage not configured' })
    }

    const data = await req.file()
    if (!data) return reply.status(400).send({ error: 'No file uploaded' })

    const mime = data.mimetype
    if (!['image/png', 'image/jpeg', 'image/webp', 'image/svg+xml'].includes(mime)) {
      return reply.status(400).send({ error: 'Unsupported image type' })
    }
    const ext = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/svg+xml': 'svg' }[mime]

    const buf = await data.toBuffer()
    const logoUrl = await spaces.uploadLogo(req.params.id, buf, mime, ext)

    await query(`UPDATE stations SET logo_url=$1, updated_at=NOW() WHERE id=$2`, [logoUrl, req.params.id])
    return { ok: true, logo_url: logoUrl }
  })
}

async function runValidation(station, siUrl) {
  try {
    const result = await validate(station, siUrl)
    await query(`
      UPDATE provisioning_status
      SET dns_valid=$2, srv_valid=$3, si_reachable=$4, stream_reachable=$5, last_validated=NOW(), updated_at=NOW()
      WHERE station_id=$1
    `, [station.id, result.dns_valid, result.srv_valid, result.si_reachable, result.stream_reachable])
  } catch (e) {
    console.error('[validate]', station.id, e.message)
  }
}
