import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'

const REGION = process.env.DO_SPACES_REGION || 'atl1'
const BUCKET = process.env.DO_SPACES_BUCKET || ''
const EPG_CDN = process.env.EPG_CDN_URL || 'https://epg.zerotrustradio.org'

let _client = null

function client() {
  if (!_client) {
    _client = new S3Client({
      region: 'us-east-1',
      endpoint: `https://${REGION}.digitaloceanspaces.com`,
      credentials: {
        accessKeyId: process.env.DO_SPACES_KEY || '',
        secretAccessKey: process.env.DO_SPACES_SECRET || '',
      },
    })
  }
  return _client
}

export async function uploadSI(stationId, xml) {
  const key = `radiodns/spi/3.1/${stationId}/SI.xml`
  await client().send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: xml,
    ContentType: 'application/xml',
    ACL: 'public-read',
    CacheControl: 'public, max-age=3600',
  }))
  return `${EPG_CDN}/${key}`
}

export async function uploadLogo(stationId, buffer, mimeType, ext) {
  const key = `radiodns/logos/${stationId}/logo.${ext}`
  await client().send(new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    Body: buffer,
    ContentType: mimeType,
    ACL: 'public-read',
    CacheControl: 'public, max-age=86400',
  }))
  return `${EPG_CDN}/${key}`
}

export function isConfigured() {
  return Boolean(BUCKET && process.env.DO_SPACES_KEY && process.env.DO_SPACES_SECRET)
}
