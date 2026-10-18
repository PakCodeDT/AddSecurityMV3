'use strict';
/**
 * Hosts-format satırları AdGuard/uBO ağ kuralı formatına çevirir.
 *
 * Desteklenen girdiler:
 *  - `127.0.0.1 example.com` / `0.0.0.0 example.com ...` (hosts)
 *  - `example.com` (çıplak domain)
 *  - `*.example.com` (wildcard hosts)
 *  - Zaten adblock formatında olan satırlar aynen geçirilir (`||`, `@@`, `/regex/`, `##`, `#$#`, `$` ...)
 *  - Yorumlar (`#`, `!`, `[`) ve boş satırlar elenir (null döner)
 *
 * Service Worker-safe: DOM yok, saf string işlemi.
 */

const HOSTS_IP_RE = /^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::|0::0)\s+/i;
const IP_ONLY_RE = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i;
const DOMAIN_RE = /^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,}$/i;

function isAdblockRule(line) {
  const t = line.trim();
  if (!t) return false;
  if (t.startsWith('@@')) return true;
  if (t.startsWith('||')) return true;
  if (t.startsWith('/') && t.length > 1) return true;
  if (t.includes('##') || t.includes('#$#') || t.includes('#@#') || t.includes('#?#') || t.includes('+js(')) return true;
  if (t.includes('$') && /[$][a-z~]/i.test(t)) return true;
  if (t.includes('://') || t.includes('/') || t.includes('*') || t.includes('^') || t.includes('|')) return true;
  return false;
}

/** Tek hosts/domain satırını adblock kuralına çevirir, geçersizse null. */
function hostsLineToAdblock(rawLine) {
  if (rawLine === null || rawLine === undefined) return null;
  let line = String(rawLine).trim();
  if (!line) return null;
  // Zaten adblock sözdizimindeyse (jenerik `##.reklam` dahil) aynen geçir;
  // satır-içi `# yorum` temizliği yalnızca hosts satırlarına uygulanır.
  // (Önce burada bakılır, yoksa `##...` satırlar aşağıdaki yorum
  // eleğine takılıp çöpe giderdi.)
  if (isAdblockRule(line)) {
    // hosts IP'si ile başlayan adblock kuralı olamaz; hosts ise aşağıda çözülür.
    if (!HOSTS_IP_RE.test(line)) return line;
  }
  // Satır içi yorum: `0.0.0.0 evil.com # yorum`
  const hashIdx = line.indexOf('#');
  if (hashIdx === 0) return null;
  if (hashIdx > 0 && /\s/.test(line[hashIdx - 1])) line = line.slice(0, hashIdx).trim();
  if (!line) return null;
  if (line.startsWith('!') || line.startsWith('[')) return null;

  // Hosts satırı: `IP host1 host2 ...`
  const tokens = line.split(/\s+/);
  let hosts;
  if (HOSTS_IP_RE.test(line) || (tokens.length > 1 && IP_ONLY_RE.test(tokens[0]))) {
    hosts = tokens.slice(1);
  } else if (tokens.length === 1) {
    hosts = tokens;
  } else {
    return null;
  }

  const out = [];
  for (let h of hosts) {
    h = h.trim().toLowerCase().replace(/\.+$/, '');
    if (!h || h === 'localhost' || h === 'localhost.localdomain' || h === 'broadcasthost') continue;
    if (IP_ONLY_RE.test(h)) continue;
    if (h.startsWith('*.')) h = h.slice(2);
    if (!DOMAIN_RE.test(h)) continue;
    out.push('||' + h + '^');
  }
  if (out.length === 0) return null;
  return out.length === 1 ? out[0] : out;
}

/** Çok satırlı liste metnini normalize eder (hosts + adblock karışık). */
function normalizeListText(text) {
  if (!text) return '';
  const out = [];
  for (const raw of String(text).split('\n')) {
    const conv = hostsLineToAdblock(raw);
    if (conv === null) continue;
    if (Array.isArray(conv)) out.push(...conv);
    else out.push(conv);
  }
  return out.join('\n');
}

// --- İNDİRME-ZAMANI TEMİZLİK (DNR/MV3 dönüşümünden ÖNCE) ---
// Engellenen TLD'ler (.click/.top/.mov/.zip) session kurallarıyla toptan
// engellenir; bu TLD'lere dokunan satırlar (block VE @@ istisna dahil)
// DNR havuzuna girmeden burada atılır. TLD = host adının EN SON etiketidir
// (`.click.com` -> TLD com, elenmez). core.js'teki ruleTextUsesBlockedTLD
// ile aynı kuralın satır-seviyesi karşılığıdır.
const BLOCKED_TLD_RE = /\.(click|top|mov|zip)([\^\/\|\$,\s\)\:\;\=\]\}\"\'\!\?]|$)/i;

function lineUsesBlockedTLD(line) {
  if (!line) return false;
  return BLOCKED_TLD_RE.test(String(line));
}

// DNR'a çevrilemeyecek kadar anlamsız satırlar (string seviyesi, muhafazakar):
//  - yalnızca-joker (`*`, `**`) -> DNR 'wildcard-only'
//  - `||*` öneki -> DNR 'invalid-anchor'
//  - tek başına `||`, `@@`, `@@||`
//  - desensiz seçenek (`$script`, `@@$script` gibi; desen yok)
//  - kaldırılan sahte-site formatı (`{orijinal;sahte,...}`, `[orijinal;sahte,...]`)
// Kozmetik (`##`, `#$#`...), regex (`/.../`) satırlarına dokunulmaz.
function isMeaninglessLine(line) {
  const l = String(line).trim();
  if (!l) return true;
  if ((l.startsWith('{') && l.endsWith('}')) || (l.startsWith('[') && l.endsWith(']'))) return true;
  if (/^\*+$/.test(l)) return true;
  if (l.startsWith('||*')) return true;
  if (l === '||' || l === '@@' || l === '@@||') return true;
  if (/^@@?\$[^\s\/]*$/.test(l)) return true;
  if (/^\$[^\s\/]*$/.test(l)) return true;
  return false;
}

/**
 * Ham liste metnini (hosts/adblock karışık) DNR/MV3 dönüşümüne girmeden ÖNCE
 * tek geçişte temizler:
 *  1. hosts satırları `||domain^` adblock formatına çevrilir,
 *  2. engellenen TLD'ye dokunan satırlar atılır,
 *  3. anlamsız satırlar (joker-tek, desensiz, `||*`) atılır,
 *  4. birebir eşleşen (duplicate) satırlar tekilleştirilir.
 * Döner: { text, stats }. `stripBlockedTld:false` verilirse TLD eleği atlanır.
 */
function sanitizeListText(text, opts) {
  const stripBlockedTld = !opts || opts.stripBlockedTld !== false;
  const stats = { inLines: 0, keptLines: 0, strippedBlockedTld: 0, strippedDuplicates: 0, strippedMeaningless: 0 };
  if (!text) return { text: '', stats };
  const seen = new Set();
  const out = [];
  for (const raw of String(text).split('\n')) {
    stats.inLines++;
    const conv = hostsLineToAdblock(raw);
    if (conv === null) continue;
    const lines = Array.isArray(conv) ? conv : [conv];
    for (let line of lines) {
      line = String(line).trim();
      if (!line) continue;
      // Not: kaldırılan `{...}`/`[...]` sahte-site formatı isMeaninglessLine
      // tarafından elenir (buraya ulaşsa bile atılır).
      if (stripBlockedTld && lineUsesBlockedTLD(line)) { stats.strippedBlockedTld++; continue; }
      if (isMeaninglessLine(line)) { stats.strippedMeaningless++; continue; }
      if (seen.has(line)) { stats.strippedDuplicates++; continue; }
      seen.add(line);
      out.push(line);
    }
  }
  stats.keptLines = out.length;
  return { text: out.join('\n'), stats };
}

// Node (build scripti) + Service Worker (ESM import) + klasik background uyumu.
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { hostsLineToAdblock, normalizeListText, isAdblockRule, sanitizeListText, isMeaninglessLine, lineUsesBlockedTLD, BLOCKED_TLD_RE };
}
if (typeof globalThis !== 'undefined') {
  globalThis.AdSecHosts = { hostsLineToAdblock, normalizeListText, isAdblockRule, sanitizeListText, isMeaninglessLine, lineUsesBlockedTLD, BLOCKED_TLD_RE };
}
