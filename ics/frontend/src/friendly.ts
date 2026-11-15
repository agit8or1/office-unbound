// Plain-language wording for raw technical failure text (TLS, DNS, sockets, timeouts, HTTP). The raw text is never thrown away:
// views show the plain sentence and keep the original inside a "Technical details" expander (see ui/TechText.vue).
const RULES: [RegExp, string][] = [
  [/WRONG_VERSION_NUMBER|wrong version number/i, 'The service did not answer with a secure (TLS) connection. It may be listening on a plain-text port, or the address or port is wrong.'],
  [/CERTIFICATE_VERIFY_FAILED|certificate verify failed|self[- ]signed|unable to get local issuer|UNKNOWN_CA/i, 'The service presented a certificate this console does not trust. Check the pinned fingerprint or the CA certificate on the check.'],
  [/certificate has expired|CERTIFICATE_EXPIRED/i, 'The service certificate has expired. Renew it on the service.'],
  [/hostname .*(mismatch|doesn't match)|IP address mismatch|HOSTNAME_MISMATCH/i, 'The certificate does not match the address being checked.'],
  [/SSLError|SSL:|TLS|handshake|SSLV3_ALERT|TLSV1_ALERT/i, 'A secure connection to the service could not be established.'],
  [/ConnectionRefused|Connection refused|ECONNREFUSED/i, 'The service refused the connection. It is probably stopped or listening on another port.'],
  [/ConnectionReset|Connection reset|BrokenPipe|RemoteDisconnected|ECONNRESET|IncompleteRead/i, 'The service closed the connection unexpectedly.'],
  [/Name or service not known|Temporary failure in name resolution|gaierror|getaddrinfo|NXDOMAIN|nodename nor servname/i, 'The address could not be resolved. Check the host name or DNS.'],
  [/No route to host|Network is unreachable|EHOSTUNREACH|ENETUNREACH/i, 'The service cannot be reached from the console server (no network route).'],
  [/ReadTimeout|ConnectTimeout|TimeoutError|timed out|socket\.timeout|overall deadline/i, 'The service did not answer in time.'],
  [/IMAP login rejected|LOGIN failed|AUTHENTICATIONFAILED|authentication failed|invalid credentials/i, 'The service rejected the stored sign-in. Check the account name and password on the check.'],
  [/check error: /i, 'The check could not complete because of an unexpected problem.'],
  [/HTTPStatusError|HTTP [45]\d\d|status [45]\d\d/i, 'The service answered with an error.'],
  [/OSError|ConnectError|HTTPError|NetworkError/i, 'The service could not be reached.'],
]

/** Returns a plain sentence when `raw` looks like a technical error, else null (the text is already readable). */
export function friendly(raw: string | null | undefined): string | null {
  if (!raw) return null
  for (const [re, text] of RULES) if (re.test(raw)) return text
  return null
}
