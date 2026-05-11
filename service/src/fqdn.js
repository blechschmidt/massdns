const ZONE = process.env.PDNS_ZONE || 'radiodns.zerotrustradio.org'
const EPG_HOST = process.env.EPG_HOST || 'epg.zerotrustradio.org'

const PI_RE = /^[0-9a-f]{4}$/
const ECC_RE = /^[0-9a-f]{2}$/

export function normalizePI(raw) {
  const s = String(raw || '').trim().toLowerCase().replace(/^0x/, '')
  if (!PI_RE.test(s)) throw new Error(`Invalid PI code "${raw}" — must be 4 hex characters`)
  return s
}

export function normalizeECC(raw) {
  const s = String(raw || '').trim().toLowerCase().replace(/^0x/, '')
  if (!ECC_RE.test(s)) throw new Error(`Invalid ECC "${raw}" — must be 2 hex characters`)
  return s
}

export function parseFreq(raw) {
  const s = String(raw || '').trim().toLowerCase().replace(/mhz/, '').trim()
  if (!s) throw new Error('Frequency is required')
  let khz10
  if (s.includes('.')) {
    const mhz = parseFloat(s)
    if (isNaN(mhz)) throw new Error(`Invalid frequency "${raw}"`)
    khz10 = Math.round(mhz * 100)
  } else {
    khz10 = parseInt(s, 10)
    if (isNaN(khz10)) throw new Error(`Invalid frequency "${raw}"`)
  }
  if (khz10 < 5000 || khz10 > 15000) throw new Error(`Frequency out of range: ${raw}`)
  return khz10
}

export function toFreq5(raw) {
  return String(parseFreq(raw)).padStart(5, '0')
}

export function buildFQDN(freq5, pi, ecc) {
  return `${freq5}.${pi}.${ecc}.fm.${ZONE}`
}

export function buildSvcFQDN(callsign) {
  return `${callsign.toLowerCase().replace(/[^a-z0-9-]/g, '')}.svc.${ZONE}`
}

export function getZone() { return ZONE }
export function getEPGHost() { return EPG_HOST }
