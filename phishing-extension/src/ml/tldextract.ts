/**
 * tldextract algorithm — TypeScript port.
 * ========================================
 * Faithful port of the public-suffix matching used by the Python
 * `tldextract` package (v3.4.4) in ml-pipeline/features/lexical_extractor.py.
 *
 * Why this exists: the extractor previously resolved domains with a 14-entry
 * hardcoded TLD dict, while training used tldextract's full Public Suffix List.
 * On country/compound TLDs and IP hosts the browser therefore computed
 * DIFFERENT DomainLength / NoOfSubDomain values than the model was trained on —
 * a train/serve skew (see ml-pipeline/check_parity.py). This port makes the
 * two sides agree by running the identical algorithm over the identical rule
 * set (src/ml/psl-trie.ts, generated from the same tldextract snapshot).
 *
 * Ported 1:1 from tldextract/_PublicSuffixListTLDExtractor.suffix_index and
 * TLDExtract._extract_netloc, including:
 *   - longest-match suffix walk with wildcard ("*.foo") and exception
 *     ("!foo.bar") rules;
 *   - RFC 3492 punycode decoding of input labels (the rule set is stored
 *     decoded, exactly as tldextract's snapshot is);
 *   - IP-host handling: when no suffix matches and the netloc is an IPv4
 *     address, the whole netloc becomes the "domain" with an empty suffix.
 */

import { PUBLIC_SUFFIX_RULES } from "./psl-trie";

export interface TldParts {
  subdomain: string;
  domain: string;
  suffix: string;
}

interface TrieNode {
  matches: Record<string, TrieNode>;
  end: boolean;
}

function makeNode(end = false): TrieNode {
  return { matches: {}, end };
}

/** Mirror of tldextract.Trie.create — insert each rule's labels in reverse. */
function buildTrie(rules: readonly string[]): TrieNode {
  const root = makeNode();
  for (const rule of rules) {
    let node = root;
    const labels = rule.split(".");
    for (let k = labels.length - 1; k >= 0; k--) {
      const label = labels[k];
      if (!(label in node.matches)) node.matches[label] = makeNode();
      node = node.matches[label];
    }
    node.end = true;
  }
  return root;
}

// ---------------------------------------------------------------------------
// Punycode (RFC 3492) decoding — input labels are decoded before lookup because
// tldextract's snapshot stores IDN rules in decoded (unicode) form.
// ---------------------------------------------------------------------------

function decodePunycodeLabel(input: string): string {
  if (!input.startsWith("xn--")) return input;

  const base = 36;
  const tmin = 1;
  const tmax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 128;

  let text = input.slice(4);
  const out: number[] = [];

  // Copy basic code points up to and including the last delimiter.
  const delimIdx = text.lastIndexOf("-");
  if (delimIdx > 0) {
    for (let j = 0; j < delimIdx; j++) out.push(text.charCodeAt(j));
    text = text.slice(delimIdx + 1);
  }

  let n = initialN;
  let i = 0;
  let bias = initialBias;

  const adapt = (delta: number, numPoints: number, firstTime: boolean): number => {
    let d = firstTime ? Math.floor(delta / damp) : delta >> 1;
    d += Math.floor(d / numPoints);
    let k = 0;
    while (d > ((base - tmin) * tmax) >> 1) {
      d = Math.floor(d / (base - tmin));
      k += base;
    }
    return k + Math.floor(((base - tmin + 1) * d) / (d + skew));
  };

  while (text.length > 0) {
    const oldi = i;
    let w = 1;
    for (let k = base; ; k += base) {
      if (text.length === 0) {
        // Malformed input — mirror idna.decode's fallback of returning the
        // label unchanged.
        return input;
      }
      const code = text.charCodeAt(0);
      text = text.slice(1);
      // RFC 3492: letters a-z = digits 0-25, digits 0-9 = digits 26-35.
      let digit: number;
      if (code >= 97) digit = code - 97;
      else if (code >= 65) digit = code - 65;
      else digit = code - 48 + 26;
      if (digit < 0 || digit >= base) return input;
      i += digit * w;
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const outLen = out.length + 1;
    bias = adapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    out.splice(i, 0, n);
    i++;
  }

  let result = "";
  for (const cp of out) result += String.fromCharCode(cp);
  return result;
}

function decodeLabel(label: string): string {
  return decodePunycodeLabel(label.toLowerCase());
}

// ---------------------------------------------------------------------------
// Netloc extraction
// ---------------------------------------------------------------------------

/** Mirror of tldextract.remote.lenient_netloc — extracts the netloc (hostname,
 * no port) from a URL-like string WITHOUT percent-decoding or IDNA-encoding,
 * exactly as Python's tldextract sees it. (The WHATWG `URL.hostname` decodes
 * percent-escapes and converts IDNs to punycode, which would diverge from the
 * training features.) */
export function rawHost(url: string): string {
  // _schemeless_url: strip the scheme, if present and valid.
  const d = url.indexOf("//");
  let host: string;
  if (d === 0) {
    host = url.slice(2);
  } else if (
    d < 2 ||
    url[d - 1] !== ":" ||
    !/^[A-Za-z0-9+\-.]*$/.test(url.slice(0, d - 1))
  ) {
    host = url;
  } else {
    host = url.slice(d + 2);
  }
  // lenient_netloc: partition on / ? #, take part after the last @, strip :port,
  // then trim and strip trailing dots.
  host = host.split("/")[0].split("?")[0].split("#")[0];
  const at = host.lastIndexOf("@");
  if (at !== -1) host = host.slice(at + 1);
  host = host.split(":")[0].trim();
  return host.replace(/[\u002e\u3002\uff0e\uff61]+$/, "");
}

/** Mirror of Python urllib.parse.urlparse(url).path — the raw path component,
 * WITHOUT WHATWG percent-encoding (which would diverge from training for
 * unicode / escaped paths). */
export function rawPath(url: string): string {
  const d = url.indexOf("//");
  const after = (d !== -1 ? url.slice(d + 2) : url).split("?")[0].split("#")[0];
  const slash = after.indexOf("/");
  return slash === -1 ? "" : after.slice(slash);
}

// ---------------------------------------------------------------------------
// Public suffix matching
// ---------------------------------------------------------------------------

/**
 * Return the index of the first suffix label in `labels`.
 * Returns labels.length when no suffix is found.
 * Mirror of tldextract._PublicSuffixListTLDExtractor.suffix_index.
 */
function suffixIndex(labels: string[]): number {
  let node = trie;
  let i = labels.length;
  let j = labels.length;
  for (let idx = labels.length - 1; idx >= 0; idx--) {
    const decoded = decodeLabel(labels[idx]);
    if (decoded in node.matches) {
      j -= 1;
      if (node.matches[decoded].end) i = j;
      node = node.matches[decoded];
      continue;
    }
    const isWildcard = "*" in node.matches;
    if (isWildcard) {
      const isWildcardException = "!" + decoded in node.matches;
      if (isWildcardException) return j;
      return j - 1;
    }
    break;
  }
  return i;
}

/** Mirror of tldextract.remote.IP_RE — strict dotted-quad IPv4. */
const IP_RE =
  /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;

/**
 * Split a hostname (no scheme, no port, no trailing dot) into subdomain /
 * domain / suffix exactly like tldextract.extract on the same netloc.
 */
export function parseHost(hostname: string): TldParts {
  // Mirror tldextract.remote.lenient_netloc: strip trailing dots (ASCII and
  // full-width variants) so "example.com." and "example.com" are identical.
  const cleaned = hostname.replace(/[\u002e\u3002\uff0e\uff61]+$/, "");
  const labels = cleaned.split(".");

  const suffixIdx = suffixIndex(labels);

  if (
    suffixIdx === labels.length &&
    cleaned.length > 0 &&
    IP_RE.test(cleaned)
  ) {
    return { subdomain: "", domain: cleaned, suffix: "" };
  }

  const suffix =
    suffixIdx !== labels.length ? labels.slice(suffixIdx).join(".") : "";
  const subdomain =
    suffixIdx >= 2 ? labels.slice(0, suffixIdx - 1).join(".") : "";
  const domain = suffixIdx ? labels[suffixIdx - 1] : "";
  return { subdomain, domain, suffix };
}

const trie = buildTrie(PUBLIC_SUFFIX_RULES);
