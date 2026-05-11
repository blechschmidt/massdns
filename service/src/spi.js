function xmlEsc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

export function generateSI(station) {
  const { callsign, frequency, pi, ecc, freq5, stream_url, website_url, logo_url, country } = station
  const serviceId = `${ecc}.${pi}.${freq5}.fm`
  const bearerURI = `fm:${ecc}.${pi}.${freq5}`
  const langAttr = country ? ` xml:lang="${xmlEsc(country.toLowerCase().slice(0, 2))}"` : ' xml:lang="en"'

  const mediaBlock = logo_url ? `
      <mediaDescription>
        <multimedia url="${xmlEsc(logo_url)}" type="logo_colour_square" mimeValue="image/png" width="128" height="128"/>
        <multimedia url="${xmlEsc(logo_url)}" type="logo_colour_rectangle" mimeValue="image/png" width="320" height="240"/>
      </mediaDescription>` : ''

  const streamBlock = stream_url ? `
      <link uri="${xmlEsc(stream_url)}" mimeValue="audio/mpeg"/>` : ''

  const descBlock = website_url ? `
      <onlineDescription>
        <textual${langAttr}>
          <shortDescription>${xmlEsc(callsign)} — ${xmlEsc(frequency)} MHz</shortDescription>
        </textual>
        <multimedia url="${xmlEsc(website_url)}" type="website"/>
      </onlineDescription>` : ''

  return `<?xml version="1.0" encoding="UTF-8"?>
<serviceInformation
  xmlns="http://www.radiodns.org/2009/01"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://www.radiodns.org/2009/01 http://www.radiodns.org/2009/01/radiodns-spi-3.1.xsd"
  version="1" creationTime="${new Date().toISOString()}">
  <services>
    <serviceProvider>
      <shortName>ZTR</shortName>
      <longName>Zero Trust Radio</longName>
    </serviceProvider>
    <service>
      <serviceID id="${serviceId}" type="fm"/>
      <shortName>${xmlEsc(callsign)}</shortName>
      <longName>${xmlEsc(callsign)} ${xmlEsc(frequency)} MHz</longName>${mediaBlock}${descBlock}
      <bearer bearerURI="${bearerURI}" bitrate="128"/>
      <radiodns fqdn="${xmlEsc(station.fqdn)}" serviceIdentifier="${xmlEsc(callsign)}"/>${streamBlock}
    </service>
  </services>
</serviceInformation>
`
}
