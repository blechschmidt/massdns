const API_URL = process.env.PDNS_API_URL || 'http://147.182.190.208:8081/api/v1'
const API_KEY = process.env.PDNS_API_KEY || ''
const ZONE = process.env.PDNS_ZONE || 'radiodns.zerotrustradio.org'
const SERVER = process.env.PDNS_SERVER || 'localhost'
const TTL = parseInt(process.env.PDNS_TTL || '300')

function abs(name) {
  return name.replace(/\.+$/, '') + '.'
}

function headers() {
  return { 'X-API-Key': API_KEY, 'Content-Type': 'application/json' }
}

function zoneUrl() {
  return `${API_URL.replace(/\/$/, '')}/servers/${SERVER}/zones/${abs(ZONE)}`
}

async function patchZone(rrsets) {
  const res = await fetch(zoneUrl(), {
    method: 'PATCH',
    headers: headers(),
    body: JSON.stringify({ rrsets }),
    signal: AbortSignal.timeout(10_000),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`PowerDNS ${res.status}: ${text.slice(0, 200)}`)
  }
}

export async function upsertCNAME(name, target, ttl = TTL) {
  await patchZone([{
    name: abs(name),
    type: 'CNAME',
    ttl,
    changetype: 'REPLACE',
    records: [{ content: abs(target), disabled: false }],
  }])
}

export async function upsertSRV(name, priority, weight, port, target, ttl = TTL) {
  await patchZone([{
    name: abs(name),
    type: 'SRV',
    ttl,
    changetype: 'REPLACE',
    records: [{ content: `${priority} ${weight} ${port} ${abs(target)}`, disabled: false }],
  }])
}

export async function deleteRRSet(name, type) {
  await patchZone([{ name: abs(name), type: type.toUpperCase(), changetype: 'DELETE' }])
}

export async function getStatus() {
  try {
    const res = await fetch(zoneUrl(), {
      headers: headers(),
      signal: AbortSignal.timeout(5_000),
    })
    if (!res.ok) return { ok: false, status: res.status }
    const data = await res.json()
    return { ok: true, zone: ZONE, rrsets: data.rrsets?.length ?? 0 }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}
