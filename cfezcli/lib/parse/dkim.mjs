// Pure DKIM key record parser. RFC 6376.
export function isDKIMName(name) {
  return /(^|\.)_domainkey\./i.test(String(name || ''));
}

export function parseDKIM(text) {
  const out = { tags: {}, errors: [], bits: null };
  for (const part of String(text || '').split(';').map(s => s.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq < 0) { out.errors.push(`malformed tag '${part}'`); continue; }
    out.tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
  }
  const t = out.tags;
  if (t.v && t.v.toUpperCase() !== 'DKIM1') out.errors.push('v must be DKIM1');
  if (t.p === undefined) out.errors.push('no p= public key tag');
  else if (t.p === '') out.errors.push('p= is empty — this selector is REVOKED');
  if (t.k && !['rsa', 'ed25519'].includes(t.k.toLowerCase())) out.errors.push(`unusual k='${t.k}'`);
  if (t.p) out.bits = estimateBits(t.p, t.k);
  return out;
}

// Approximate modulus size from base64 DER length. Reliably separates
// 512 / 1024 / 2048+, which is all the findings turn on.
export function estimateBits(p, k) {
  if ((k || 'rsa').toLowerCase() === 'ed25519') return 256;
  const bytes = Math.floor(p.replace(/[^A-Za-z0-9+/=]/g, '').length * 3 / 4);
  if (bytes > 500) return 4096;
  if (bytes > 350) return 3072;
  if (bytes > 250) return 2048;
  if (bytes > 120) return 1024;
  return 512;
}
