// Pure SPF record parser. No I/O, no DNS. RFC 7208.
export const QUALIFIERS = ['+', '-', '~', '?'];
export const LOOKUP_MECHANISMS = ['include', 'a', 'mx', 'ptr', 'exists'];
const KNOWN = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'];

export function isSPF(text) {
  return /^v=spf1(\s|$)/i.test(String(text || '').trim());
}

export function parseSPF(text) {
  const terms = String(text || '').trim().split(/\s+/).filter(Boolean);
  if (!/^v=spf1$/i.test(terms[0] || '')) {
    return { valid: false, reason: 'does not begin with v=spf1', mechanisms: [], modifiers: [], errors: [] };
  }
  const out = { valid: true, mechanisms: [], modifiers: [], errors: [] };
  for (const term of terms.slice(1)) {
    const eq = term.indexOf('=');
    if (eq > 0 && !/^exists/i.test(term)) {
      const key = term.slice(0, eq).toLowerCase();
      if (key === 'redirect' || key === 'exp') {
        out.modifiers.push({ key, value: term.slice(eq + 1) });
      } else {
        out.errors.push(`unknown modifier '${term}'`);
      }
      continue;
    }
    let qualifier = '+', body = term;
    if (QUALIFIERS.includes(term[0])) { qualifier = term[0]; body = term.slice(1); }
    const colon = body.indexOf(':');
    const name = (colon < 0 ? body : body.slice(0, colon)).toLowerCase();
    const value = colon < 0 ? '' : body.slice(colon + 1);
    if (!KNOWN.includes(name)) { out.errors.push(`unknown mechanism '${term}'`); continue; }
    out.mechanisms.push({ qualifier, name, value, raw: term });
  }
  return out;
}

// Mechanisms that cost a DNS lookup, per RFC 7208 §4.6.4.
export function lookupTerms(parsed) {
  const terms = parsed.mechanisms.filter(m => LOOKUP_MECHANISMS.includes(m.name));
  const redirect = parsed.modifiers.find(m => m.key === 'redirect');
  return { terms, redirect: redirect ? redirect.value : null };
}
