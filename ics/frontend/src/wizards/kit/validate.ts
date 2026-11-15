export type Errors = Record<string, string>
export const isEmpty = (e: Errors) => Object.keys(e).length === 0

const HOST_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/
export function isIpv4(s: string): boolean { return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every((o) => Number(o) <= 255) }
export function isHost(s: string): boolean { return isIpv4(s) || (HOST_RE.test(s) && s.length <= 253 && !/^\d+(\.\d+)*$/.test(s)) }
export const isPort = (n: number) => Number.isInteger(n) && n >= 1 && n <= 65535
export const SLUG_RE = /^[a-z0-9][a-z0-9_-]{0,62}$/
export const TOKEN_ID_RE = /^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z0-9._-]+$/
export const TOKEN_SECRET_RE = /^[A-Za-z0-9_-]{8,200}$/
export const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i
export const POOL_RE = /^[A-Za-z][A-Za-z0-9_-]{0,63}$/

/** SHA-256 fingerprint: 32 hex bytes, with or without colons; returned as upper-case colon form, or null. */
export function normalizeFingerprint(s: string): string | null {
  const hex = s.trim().replace(/^(?:sha-?256\s*)?fingerprint\s*=\s*/i, '').replace(/[:\s-]/g, '')
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return null
  return hex.toUpperCase().match(/../g)!.join(':')
}
export function looksLikePem(s: string): boolean {
  return /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.test(s)
}
export const intIn = (n: number, lo: number, hi: number) => Number.isInteger(n) && n >= lo && n <= hi
