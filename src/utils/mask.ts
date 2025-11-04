export const maskEmail = (email: string): string => {
  if (!email || typeof email !== 'string') return ''

  const parts = email.split('@')
  const name = parts[0] || ''
  const domain = parts[1] || ''

  if (!name || !domain) return '***'

  const visible = name.length <= 2 ? name : `${name.slice(0, 2)}***`
  return `${visible}@${domain}`
}
