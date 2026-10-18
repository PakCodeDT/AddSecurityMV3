'use strict';
/**
 * FilterRule (core.js) -> Declarative Net Request kuralı çevirici.
 * Service Worker-safe: DOM yok, bağımlılık yok.
 *
 * Kapsam:
 *  - block / allow (istisna) -> DNR block/allow
 *  - $important -> yüksek priority
 *  - $redirect=http/data -> DNR redirect
 *  - $removeparam -> DNR removeParams
 *  - domain/to -> requestDomains, domain-mod/from/denyallow -> initiator/excluded
 *  - 3p/1p -> domainType, tip modifikatörleri -> resourceTypes
 *  - regex -> regexFilter (RE2 uyumsuzsa skip)
 *
 * Bilerek DNR'a alınMAyanlar (gerekçesiyle skipped'e yazılır):
 *  cosmetic, scriptlet, CSP, cookie, replace, uritransform, popup,
 *  $method/$header (DNR koşulu yok), $permissions, $all/$genericblock/$generichide...,
 *  $~document gibi negatif document, prosedürel/HTML filtreleri.
 *  (Engellenen TLD + birebir eşleşen metin eleği indirme anında yapılır —
 *  lib/hosts.js sanitizeListText — buraya kirli satır ulaşmaz.)
 *
 * ÖNCELİK BANTLARI (Tier3 "Kural Tanımaz" koruması):
 *  DNR eşleşen kurallar arasından en yüksek priority'liyi seçer (eşitlikte
 *  allow kazanır). Tier3 bir filtrenin engelleme kuralı, kendi filtresi
 *  HARİÇ hiçbir filtrenin @@ kuralıyla ezilemesin diye:
 *   300000 own-exception : Tier3 bloğu hedefleyen AYNI liste @@ kuralı
 *   200000 master-block   : Tier3 (UNRULY) engelleme/$redirect/$removeparam
 *   100001 allow          : normal @@ (Tier3 @@ dahil, yabancı Tier3 bloğunu ezemez)
 *    20000 important      : $important engelleme
 *     5000 special       : normal $redirect/$removeparam
 *        1 block         : normal engelleme
 *  masterSet: Tier3 engelleme kuralı nesneleri (kimlik/ref ile).
 *  masterDomainsByList: { listId: Set(domain) } — AYNI listenin, AYNI hedef
 *  domaine yazılmış @@ kuralı "kendi filtresi" sayılır ve 300000 alır.
 */
const DNR_PRIORITY = {
  BLOCK: 1,
  SPECIAL: 5000,
  IMPORTANT: 20000,
  ALLOW: 100001,
  MASTER_BLOCK: 200000,
  OWN_EXCEPTION: 300000,
};

const DNR_TYPE_MAP = {
  script: 'script',
  image: 'image',
  stylesheet: 'stylesheet',
  object: 'object',
  xmlhttprequest: 'xmlhttprequest',
  fetch: 'xmlhttprequest',
  media: 'media',
  font: 'font',
  websocket: 'websocket',
  document: 'main_frame',
  main_frame: 'main_frame',
  sub_frame: 'sub_frame',
  frame: 'sub_frame',
  ping: 'ping',
  other: 'other',
  csp_report: 'csp_report',
};

function hashId(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = (((h << 5) + h) + str.charCodeAt(i)) >>> 0;
  return (h % 2147483646) + 1; // DNR id >= 1
}

function cleanDomainList(list) {
  const pos = [], neg = [];
  for (const d of (list || [])) {
    if (!d) continue;
    const s = String(d.domain || d).trim().toLowerCase().replace(/^\*\./, '').replace(/\.+$/, '');
    if (!s) continue;
    if (d.negated || String(d).startsWith('~') || (typeof d === 'string' && d.startsWith('~'))) neg.push(s.replace(/^~/, ''));
    else pos.push(s);
  }
  return { pos, neg };
}

function splitModifierDomains(list) {
  const pos = [], neg = [];
  for (const d of (list || [])) {
    const s = String(d).trim();
    if (!s) continue;
    if (s.startsWith('~')) neg.push(s.slice(1).toLowerCase());
    else pos.push(s.toLowerCase());
  }
  return { pos, neg };
}

/** Tek FilterRule -> DNR kuralı (dönüştürülemezse {skipped: reason}). */
function filterRuleToDnr(rule, opts = {}) {
  if (!rule || typeof rule !== 'object') return { skipped: 'empty-rule' };
  if (rule.isCosmetic || rule.isScriptlet) return { skipped: 'cosmetic-scriptlet' };
  if (rule.isCSP || rule.isCookie || rule.isReplace || rule.isUriTransform || rule.isPermissions) {
    return { skipped: 'unsupported-modifier' };
  }
  if (rule.isPopup) return { skipped: 'popup-needs-webnavigation' };
  if (rule.isGenericHide || rule.isSpecificHide || rule.isElemHide || rule.isGenericBlock) {
    return { skipped: 'hide-block-hint' };
  }
  if (rule.isBadFilter) return { skipped: 'badfilter' };
  if (rule.isMethod || rule.isHeader) return { skipped: 'method-header-unsupported' };
  if (rule.isRegex) {
    // DNR regexFilter RE2 alt kümesi ister; burada kaba eleme yapıp
    // gerçek doğrulamayı AdGuard dnr-converter'lı build scriptine bırakıyoruz.
    try {
      const src = rule.regex ? rule.regex.source : String(rule.ruleText || '').slice(1, -1);
      if (!src || /\(\?<[=!]|\(\?!|\(\?<=|\(\?<!/.test(src)) return { skipped: 'regexp-lookaround' };
      if (/[^\x00-\x7F]/.test(src)) return { skipped: 'non-ascii-regex' };
      const condition = { regexFilter: src, isUrlFilterCaseSensitive: false };
      applyDomains(condition, rule);
      applyTypes(condition, rule);
      const action = rule.isException ? { type: 'allow' } : { type: 'block' };
      return { rule: finalize(action, condition, rule, opts, 'regex:' + src) };
    } catch (e) { return { skipped: 'regexp-invalid' }; }
  }
  if (!rule.domain && !rule.path && !rule.isAll) return { skipped: 'no-pattern' };

  // --- condition ---
  const condition = {};
  const pattern = buildUrlFilter(rule);
  if (!pattern) return { skipped: 'pattern-unbuildable' };
  // DNR tek geçersiz kuralda bile updateDynamicRules'un TAMAMINI reddeder
  // (hata yutulur -> dinamik engelleme sıfırlanır). Bu yüzden şema bekçiliği:
  // ASCII zorunlu, yalnızca-joker yasak, '||*' öneki yasak.
  if (/[^\x00-\x7F]/.test(pattern)) return { skipped: 'non-ascii-urlfilter' };
  if (/^\*+$/.test(pattern)) return { skipped: 'wildcard-only' };
  if (pattern.startsWith('||*')) return { skipped: 'invalid-anchor' };
  condition.urlFilter = pattern;

  applyDomains(condition, rule);
  applyTypes(condition, rule);

  // --- action ---
  let action;
  if (rule.isRemoveParam) {
    // DNR'da bağımsız `removeParams` aksiyonu YOKTUR (RuleActionType:
    // block/redirect/allow/upgradeScheme/modifyHeaders/allowAllRequests).
    // Query temizliği `redirect` + `queryTransform.removeParams` ile yapılır;
    // yanlış tip tüm updateDynamicRules çağrısını reddettirir.
    if (rule.removeAllParams) {
      // Tüm query'yi silmek DNR'da tek aksiyonda yok -> skip (SW tarafı fallback).
      return { skipped: 'removeparam-all' };
    }
    const names = (rule.paramsToRemove || []).filter(p => typeof p === 'string' && p.length > 0).slice(0, 100);
    if (!names.length) return { skipped: 'removeparam-empty' };
    action = { type: 'redirect', redirect: { transform: { queryTransform: { removeParams: names } } } };
    return { rule: finalize(action, condition, rule, opts, null, true) };
  }
  if (rule.isRedirect) {
    const target = rule.redirectResource || '';
    if (!/^data:|^https?:\/\//i.test(target)) return { skipped: 'redirect-non-url-resource' };
    action = { type: 'redirect', redirect: { url: target } };
    return { rule: finalize(action, condition, rule, opts, null, true) };
  }
  action = rule.isException ? { type: 'allow' } : { type: 'block' };
  return { rule: finalize(action, condition, rule, opts, null, false) };
}

function buildUrlFilter(rule) {
  const d = (rule.domain || '').toLowerCase().replace(/^\*\./, '');
  let p = rule.path || '';
  // $all yalnızca tip eşleşmesini genişletir; domain/path varsa ondan kurulur.
  // (Eskiden `||evil.com^$all` -> '*' olup tüm trafiği tutuyordu.)
  if (d && !p) return '||' + d + '^';
  if (d && p) {
    // path'teki ^ ayraçları DNR urlFilter'da geçerli, tutuyoruz.
    return '||' + d + p;
  }
  if (!d && p) {
    // Çıplak pattern (_reklama_) ya da *jokerli* genel kural.
    if (p.includes('*')) return '*' + p.trim().replace(/^\*+|\*+$/g, '') + '*';
    const t = p.trim();
    if (!t) return null;
    if (/^[a-z0-9_\-.]+$/i.test(t)) return '*' + t + '*';
    return '*' + t + '*';
  }
  // Desensiz kural: $all istisnası her şeyden muaf tutar ('*'), desensiz $all
  // engelleme ise tüm trafiği öldürür -> DNR'a yazılmaz.
  if (rule.isAll) return rule.isException ? '*' : null;
  return null;
}

function applyDomains(condition, rule) {
  // İstek hedefi kısıtları: $to / $denyallow
  if (rule.isTo && rule.toDomains && rule.toDomains.length) {
    condition.requestDomains = rule.toDomains.map(s => String(s).toLowerCase());
  }
  if (rule.isDenyAllow && rule.denyAllowDomains && rule.denyAllowDomains.length) {
    condition.excludedRequestDomains = rule.denyAllowDomains.map(s => String(s).toLowerCase());
  }
  // Kaynak (belge) kısıtları: $domain / $from / kozmetik domainleri değil
  const from = rule.isFrom && rule.fromDomains ? splitModifierDomains(rule.fromDomains) : { pos: [], neg: [] };
  const dom = rule.modifiers && rule.modifiers.domain ? splitModifierDomains(rule.modifiers.domain) : { pos: [], neg: [] };
  const pos = [...from.pos, ...dom.pos].filter(Boolean);
  const neg = [...from.neg, ...dom.neg].filter(Boolean);
  if (pos.length) condition.initiatorDomains = [...new Set(pos)].slice(0, 100);
  if (neg.length) condition.excludedInitiatorDomains = [...new Set(neg)].slice(0, 100);

  if (rule.modifiers && rule.modifiers.thirdParty === true) condition.domainType = 'thirdParty';
  else if (rule.modifiers && rule.modifiers.firstParty === true) condition.domainType = 'firstParty';
}

function applyTypes(condition, rule) {
  const pos = [], neg = [];
  const mods = rule.modifiers || {};
  for (const k of Object.keys(DNR_TYPE_MAP)) {
    if (mods[k] === true) pos.push(DNR_TYPE_MAP[k]);
    else if (mods[k] === false) neg.push(DNR_TYPE_MAP[k]);
  }
  // $media bayrağı core.js'te ayrıca tutulur.
  if (rule.isMedia && !pos.includes('media')) pos.push('media');
  if (pos.length) condition.resourceTypes = [...new Set(pos)].slice(0, 20);
  if (!pos.length && neg.length) condition.excludedResourceTypes = [...new Set(neg)].slice(0, 20);
}

function finalize(action, condition, rule, opts, idSeed, isSpecial) {
  opts = opts || {};
  let priority = opts.basePriority || DNR_PRIORITY.BLOCK;
  const inMasterSet = !!(opts.masterSet && opts.masterSet.has(rule));
  if (rule.isException) {
    priority = DNR_PRIORITY.ALLOW;
    // Kendi filtresi istisnası: AYNI listenin Tier3 bloğuyla AYNI hedef
    // domaine yazılmış @@, kendi bloğunu ezebilir (OWN_EXCEPTION).
    const byList = opts.masterDomainsByList;
    const lid = rule.listId;
    const dom = (rule.domain || '').toLowerCase().replace(/^\*\./, '');
    if (lid && dom && byList && byList[lid] && byList[lid].has(dom)) {
      priority = DNR_PRIORITY.OWN_EXCEPTION;
    }
  }
  else if (inMasterSet) priority = DNR_PRIORITY.MASTER_BLOCK;
  else if (rule.isImportant) priority = DNR_PRIORITY.IMPORTANT;
  else if (isSpecial) priority = DNR_PRIORITY.SPECIAL;
  const seed = idSeed || ((rule.isException ? '@@' : '') + (rule.ruleText || JSON.stringify(condition)));
  return {
    id: hashId(seed + '|' + (rule.listId || '')),
    priority,
    action,
    condition,
  };
}

/** Kural dizisini DNR'a çevirir; limit ve tekilleştirme uygular. */
function filterRulesToDnr(rules, opts = {}) {
  const max = opts.maxRules || 4500;
  const out = [], skipped = {};
  const seen = new Set();
  const bump = (r) => r;
  for (const r of (rules || [])) {
    if (out.length >= max) { skipped['limit'] = (skipped['limit'] || 0) + 1; continue; }
    // Not: birebir-eşleşen metin eleği indirme anında yapılır
    // (sanitizeListText); burada yalnızca dönüşüm-sonrası eşdeğerlik
    // (farklı metin -> aynı DNR koşulu) tekilleştirilir.
    const res = filterRuleToDnr(r, opts);
    if (!res.rule) {
      skipped[res.skipped || 'unknown'] = (skipped[res.skipped || 'unknown'] || 0) + 1;
      continue;
    }
    const key = res.rule.action.type + '|' + JSON.stringify(res.rule.condition) + '|' + JSON.stringify(res.rule.action);
    if (seen.has(key)) { skipped['duplicate'] = (skipped['duplicate'] || 0) + 1; continue; }
    seen.add(key);
    out.push(bump(res.rule));
  }
  // DNR id çakışması ihtimaline karşı yeniden numaralandırma (kararlı).
  const used = new Set();
  for (const r of out) {
    while (used.has(r.id)) r.id = (r.id % 2147483646) + 1;
    used.add(r.id);
  }
  return { rules: out, skipped };
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { filterRuleToDnr, filterRulesToDnr, hashId, DNR_PRIORITY };
}
if (typeof globalThis !== 'undefined') {
  globalThis.AdSecDnr = { filterRuleToDnr, filterRulesToDnr, hashId, DNR_PRIORITY };
}
