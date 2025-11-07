import crypto from 'crypto'

/** Generate a random token the user will receive (raw), plus an expiry Date */
export function generateVerificationTokenRaw(ttlMinutes = 15) {
  const raw = crypto.randomBytes(32).toString('hex')
  const expiresAt = new Date(Date.now() + ttlMinutes * 60 * 1000)

  return { raw, expiresAt }
}

/** Timing-safe compare of a raw token against a stored hex hash */
export function timingSafeMatch(rawToken: string, storedHexHash: string) {
  const a = crypto.createHash('sha256').update(rawToken).digest()
  const b = Buffer.from(storedHexHash, 'hex')
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}
