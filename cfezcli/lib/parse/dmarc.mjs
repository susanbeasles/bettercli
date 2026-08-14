// Pure DMARC record parser. RFC 7489.
import { isValidEmail } from './email.mjs';

export const TAGS = ['v','p','sp','rua','ruf','fo','pct','adkim','aspf','rf','ri','np'];
const POLICIES = ['none', 'quarantine', 'reject'];

export function isDMARC(text) {
  return /^v=DMARC1(\s*;|$)/i.test(String(text || '').trim());
}

export function parseDMARC(text) {
  const out = { tags: {}, order: [], errors: [] };
  const parts = String(text || '').split(';').map(s => s.trim()).filter(Boolean);

  parts.forEach((part, i) => {
    const eq = part.indexOf('=');
    if (eq < 0) { out.errors.push(`malformed tag '${part}'`); return; }
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (i === 0 && key !== 'v') out.errors.push(`first tag must be v=, got '${key}='`);
    if (!TAGS.includes(key)) out.errors.push(`unknown tag '${key}='`);
    if (key in out.tags) out.errors.push(`duplicate tag '${key}='`);
    out.tags[key] = value;
    out.order.push(key);
  });

  const t = out.tags;
  if (t.v && t.v.toUpperCase() !== 'DMARC1') out.errors.push(`v must be DMARC1, got '${t.v}'`);
  for (const k of ['p', 'sp']) {
    if (t[k] && !POLICIES.includes(t[k].toLowerCase())) out.errors.push(`invalid ${k}='${t[k]}'`);
  }
  if (t.pct !== undefined) {
    const n = Number(t.pct);
    if (!Number.isInteger(n) || n < 0 || n > 100) out.errors.push(`pct must be 0-100, got '${t.pct}'`);
  }
  for (const k of ['adkim', 'aspf']) {
    if (t[k] && !['r', 's'].includes(t[k].toLowerCase())) out.errors.push(`${k} must be r or s`);
  }
  if (t.fo) {
    const bad = t.fo.split(':').map(x => x.trim().toLowerCase()).filter(x => !['0','1','d','s'].includes(x));
    if (bad.length) out.errors.push(`invalid fo value(s): ${bad.join(',')}`);
  }
  for (const k of ['rua', 'ruf']) {
    for (const addr of reportAddresses(t[k])) {
      if (addr.error) out.errors.push(`${k} ${addr.error}`);
    }
  }
  return out;
}

// Parsed rua=/ruf= destinations. One place that knows the URI shape.
export function reportAddresses(tagValue) {
  if (!tagValue) return [];
  return tagValue.split(',').map(s => s.trim()).filter(Boolean).map(uri => {
    if (!/^mailto:/i.test(uri)) return { uri, error: `URI must be mailto: — '${uri}'` };
    const address = uri.replace(/^mailto:/i, '').split('!')[0];
    if (!isValidEmail(address)) return { uri, address, error: `has invalid email '${address}'` };
    return { uri, address, domain: address.slice(address.lastIndexOf('@') + 1).toLowerCase() };
  });
}
