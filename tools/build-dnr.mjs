#!/usr/bin/env node
/**
 * Klasördeki AdGuard kütüphanesiyle (@adguard/dnr-converter) filtreleri
 * DNR formatına çevirir.
 *
 * Kullanım:
 *   node tools/build-dnr.mjs --input filtre.txt --output dnr-rules/filtre.json
 *   node tools/build-dnr.mjs --input ./lists/ --output ./dnr-rules/ --combine
 *   node tools/build-dnr.mjs --stdin --output dnr-rules/out.json  (hosts/adblock karışık okur)
 *
 * Hosts satırları önce lib/hosts.js sanitize ile `||domain^` formatına çevrilir,
 * sonra AdGuard converter'a verilir. Converter'a vermeden ÖNCE satırlar
 * temizlenir: engellenen TLD'lere (.click/.top/.mov/.zip) dokunan kurallar
 * (block + @@ istisna dahil), anlamsız kurallar ve birebir eşleşen satırlar
 * atılır (kapatmak için: --keep-blocked-tld). SW tarafındaki indirme-zamanı
 * temizlikle aynı fonksiyondur (tek kaynak: lib/hosts.js sanitizeListText);
 * sonuç sayılar çıktı dosyasına yazılır.
 * Converter'ın atladığı kurallar raporda `errors`/`limitations` altında gösterilir.
 */
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { sanitizeListText } = require('../lib/hosts.js');
const { Filter, FilterConverter } = await import('@adguard/dnr-converter');

function parseArgs(argv) {
  const o = { input: null, output: null, combine: false, stdin: false, filterId: 1, maxRules: 30000, keepBlockedTld: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--input') o.input = argv[++i];
    else if (a === '--output') o.output = argv[++i];
    else if (a === '--combine') o.combine = true;
    else if (a === '--stdin') o.stdin = true;
    else if (a === '--filter-id') o.filterId = Number(argv[++i]);
    else if (a === '--max-rules') o.maxRules = Number(argv[++i]);
    else if (a === '--keep-blocked-tld') o.keepBlockedTld = true;
  }
  return o;
}

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

async function collectInputs(input, useStdin) {
  if (useStdin) return [{ name: 'stdin', text: await readStdin() }];
  if (!input) throw new Error('--input veya --stdin gerekli');
  const st = await import('node:fs').then(async (m) => m.promises.stat(input));
  void st;
  const { stat } = await import('node:fs/promises');
  const s = await stat(input);
  if (s.isDirectory()) {
    const files = (await readdir(input)).filter((f) => !f.startsWith('.')).sort();
    const out = [];
    for (const f of files) {
      const p = path.join(input, f);
      const t = await readFile(p, 'utf8').catch(() => null);
      if (t !== null) out.push({ name: f, text: t });
    }
    return out;
  }
  return [{ name: path.basename(input), text: await readFile(input, 'utf8') }];
}

async function convertOne(name, rawText, id, maxRules, opts = {}) {
  // DNR'a çevirmeden ÖNCE temizlik (lib/hosts.js ortak sanitize):
  // hosts->adblock çevirisi + engellenen TLD (.click/.top/.mov/.zip,
  // block VE @@ istisna dahil) + anlamsız kurallar + birebir eşleşenler
  // (kapatmak için: --keep-blocked-tld). SW tarafındaki indirme-zamanı
  // temizlikle aynı mantık; sonuç sayılar çıktı dosyasına yazılır.
  const sanitized = sanitizeListText(rawText, { stripBlockedTld: !opts.keepBlockedTld });
  const cleaned = { text: sanitized.text, keptLines: sanitized.stats.keptLines, strippedBlockedTld: sanitized.stats.strippedBlockedTld, strippedDuplicates: sanitized.stats.strippedDuplicates, strippedMeaningless: sanitized.stats.strippedMeaningless };
  const filter = new Filter(id, cleaned.text);
  const [result] = await FilterConverter.convertSimple([filter], {
    combine: true,
    maxNumberOfRules: maxRules,
  });
  return { name, normalizedLines: sanitized.stats.inLines, cleaned, result };
}

// Surrogate redirect kuralları (noop.js/1x1.gif gibi extensionPath hedefli)
// eklentide kullanılmaz: ilgili kaynak dosyalar pakette yok. Çıktıdan atılır.
function stripSurrogateRedirects(rules) {
  const kept = [];
  let stripped = 0;
  for (const r of (rules || [])) {
    const redir = r && r.action && r.action.redirect;
    if (r && r.action && r.action.type === 'redirect' && redir && redir.extensionPath) { stripped++; continue; }
    kept.push(r);
  }
  return { kept, stripped };
}

async function main() {
  const o = parseArgs(process.argv);
  const inputs = await collectInputs(o.input, o.stdin);
  if (!inputs.length) throw new Error('Çevrilecek girdi bulunamadı');

  if (o.combine || inputs.length === 1) {
    const joined = inputs.map((x) => `! ---- ${x.name} ----\n${x.text}`).join('\n');
    const { result, normalizedLines, cleaned } = await convertOne('combined', joined, o.filterId, o.maxRules, o);
    const { kept: declarativeRules, stripped: strippedSurrogates } = stripSurrogateRedirects(result.ruleset.declarativeRules);
    const payload = {
      generator: 'adsecurity/build-dnr (AdGuard dnr-converter)',
      sources: inputs.map((x) => x.name),
      normalizedLines,
      keptLines: cleaned.keptLines,
      strippedBlockedTld: cleaned.strippedBlockedTld,
      strippedDuplicates: cleaned.strippedDuplicates,
      strippedMeaningless: cleaned.strippedMeaningless,
      strippedSurrogates,
      declarativeRules,
      safeRulesCount: result.ruleset.safeRulesCount,
      unsafeRulesCount: result.ruleset.unsafeRulesCount,
      regexpRulesCount: result.ruleset.regexpRulesCount,
      errors: (result.errors || []).map(String),
      limitations: result.limitations || [],
    };
    if (!o.output) {
      process.stdout.write(JSON.stringify(payload, null, 2));
      return;
    }
    await mkdir(path.dirname(o.output), { recursive: true });
    await writeFile(o.output, JSON.stringify(payload, null, 2));
    console.log(`[build-dnr] ${inputs.length} kaynak -> ${payload.declarativeRules.length} DNR kuralı (${o.output}) [temizlik: blocked-tld=${payload.strippedBlockedTld}, duplicate=${payload.strippedDuplicates}, meaningless=${payload.strippedMeaningless}, surrogate=${payload.strippedSurrogates}]`);
    if (payload.errors.length) console.log(`[build-dnr] hata: ${payload.errors.length} (bkz. çıktı dosyası)`);
    return;
  }

  // Çoklu çıktı: her girdi ayrı JSON.
  await mkdir(o.output, { recursive: true });
  let id = o.filterId;
  for (const inp of inputs) {
    const { result, normalizedLines, cleaned } = await convertOne(inp.name, inp.text, id++, o.maxRules, o);
    const { kept: declarativeRules, stripped: strippedSurrogates } = stripSurrogateRedirects(result.ruleset.declarativeRules);
    const payload = {
      generator: 'adsecurity/build-dnr (AdGuard dnr-converter)',
      sources: [inp.name],
      normalizedLines,
      keptLines: cleaned.keptLines,
      strippedBlockedTld: cleaned.strippedBlockedTld,
      strippedDuplicates: cleaned.strippedDuplicates,
      strippedMeaningless: cleaned.strippedMeaningless,
      strippedSurrogates,
      declarativeRules,
      errors: (result.errors || []).map(String),
      limitations: result.limitations || [],
    };
    const outPath = path.join(o.output, inp.name.replace(/\.[^.]+$/, '') + '.dnr.json');
    await writeFile(outPath, JSON.stringify(payload, null, 2));
    console.log(`[build-dnr] ${inp.name} -> ${payload.declarativeRules.length} kural (${outPath})`);
  }
}

main().catch((e) => { console.error('[build-dnr] HATA:', e?.message || e); process.exit(1); });
