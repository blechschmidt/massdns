import { query } from '../db.js'
import { validate } from '../validator.js'

const EPG_CDN = process.env.EPG_CDN_URL || 'https://epg.zerotrustradio.org'

export default async function statusRoutes(fastify) {
  fastify.get('/service/status/:id', async (req, reply) => {
    const res = await query(`
      SELECT s.*, p.dns_provisioned, p.si_published, p.dns_valid, p.srv_valid,
             p.si_reachable, p.stream_reachable, p.last_validated, p.provision_log
      FROM stations s
      LEFT JOIN provisioning_status p ON p.station_id = s.id
      WHERE s.id = $1
    `, [req.params.id])
    if (!res.rows.length) return reply.status(404).send({ error: 'Not found' })

    const station = res.rows[0]
    const siUrl = `${EPG_CDN}/radiodns/spi/3.1/${station.id}/SI.xml`

    // Re-run live validation
    const live = await validate(station, siUrl)

    // Update stored state
    await query(`
      UPDATE provisioning_status
      SET dns_valid=$2, srv_valid=$3, si_reachable=$4, stream_reachable=$5,
          last_validated=NOW(), updated_at=NOW()
      WHERE station_id=$1
    `, [station.id, live.dns_valid, live.srv_valid, live.si_reachable, live.stream_reachable])

    return {
      id: station.id,
      callsign: station.callsign,
      fqdn: station.fqdn,
      si_url: siUrl,
      provisioning: {
        dns_provisioned:  station.dns_provisioned,
        si_published:     station.si_published,
      },
      health: {
        dns_valid:        live.dns_valid,
        srv_valid:        live.srv_valid,
        si_reachable:     live.si_reachable,
        stream_reachable: live.stream_reachable,
        last_validated:   new Date().toISOString(),
        detail:           live.detail,
      },
      trust_score: calcTrust(live),
    }
  })
}

function calcTrust(v) {
  const checks = [v.dns_valid, v.srv_valid, v.si_reachable].filter(x => x !== null)
  if (!checks.length) return 'unknown'
  const passed = checks.filter(Boolean).length
  if (passed === checks.length) return 'verified'
  if (passed >= checks.length / 2) return 'partial'
  return 'degraded'
}
