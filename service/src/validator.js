import dns from 'dns'
import { promisify } from 'util'

const resolveCNAME = promisify(dns.resolveCname)
const resolveSRV = promisify(dns.resolveSrv)

const TIMEOUT = 6_000

async function httpReachable(url) {
  if (!url) return null
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      signal: AbortSignal.timeout(TIMEOUT),
      redirect: 'follow',
    })
    return { ok: res.ok, status: res.status }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

async function checkCNAME(fqdn) {
  try {
    const records = await resolveCNAME(fqdn)
    return { ok: records.length > 0, target: records[0] }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

async function checkSRV(name) {
  try {
    const records = await resolveSRV(name)
    return { ok: records.length > 0, records }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

export async function validate(station, siUrl) {
  const svcBase = station.svc_fqdn
  const [cname, epgSRV, spiSRV, siCheck, streamCheck] = await Promise.allSettled([
    checkCNAME(station.fqdn),
    checkSRV(`_radioepg._tcp.${svcBase}`),
    checkSRV(`_radiospi._tcp.${svcBase}`),
    httpReachable(siUrl),
    httpReachable(station.stream_url),
  ])

  const get = r => r.status === 'fulfilled' ? r.value : { ok: false, error: r.reason?.message }

  return {
    dns_valid:        get(cname).ok,
    srv_valid:        get(epgSRV).ok && get(spiSRV).ok,
    si_reachable:     get(siCheck)?.ok ?? null,
    stream_reachable: station.stream_url ? (get(streamCheck)?.ok ?? null) : null,
    detail: {
      cname:      get(cname),
      epg_srv:    get(epgSRV),
      spi_srv:    get(spiSRV),
      si:         get(siCheck),
      stream:     station.stream_url ? get(streamCheck) : null,
    },
  }
}
