'use strict';
// MV3 service worker notu: `window` YOKTUR, yerine `globalThis` kullanılır.
// (core.js `browser` shim'ini kurar; bu dosya ondan sonra yüklenir.)
// background.js yükleme sırası: lib/hosts.js -> lib/rule-to-dnr.js -> core.js -> corest.js
const PSL_URL='https://publicsuffix.org/list/public_suffix_list.dat', PSL_REFRESH=7*24*60*60*1e3;
async function fetchPSL(){try{const r=await fetch(PSL_URL,{cache:'no-cache'}); if(r.ok)return await r.text()}catch(e){}return null}
async function loadPSL(force=!1){try{const s=await browser.storage.local.get(['adsecurity_psl_raw','adsecurity_psl_updated']); const cached=s.adsecurity_psl_raw, last=s.adsecurity_psl_updated||0, stale=force||Date.now()-last>PSL_REFRESH; let text=null, failed=!1; if(typeof cached==='string'&&cached.length&&!stale)text=cached; else{const r=await fetchPSL(); if(r){text=r; await browser.storage.local.set({adsecurity_psl_raw:r,adsecurity_psl_updated:Date.now()})}else if(typeof cached==='string'&&cached.length){text=cached; failed=!0}else failed=!0} if(text){const p=parsePSL(text); pslExactRules=p.exact; pslWildcardRules=p.wildcard; pslExceptionRules=p.exception; pslLoaded=!0} if(force&&failed)throw new Error('PSL indirilemedi'+(text?' (eski kullanılıyor)':''))}catch(e){if(force)throw e}}

// ============== DEVRE DIŞI SİTELER (YÜKLENİYOR) ==============
async function loadDisabledSites(){const d=await browser.storage.local.get('adsecurity_disabled_sites'); disabledSites=new Set(Array.isArray(d.adsecurity_disabled_sites)?d.adsecurity_disabled_sites:[])}

// ============== ÖZEL LİSTELER ==============
function genId(){return'custom_'+Date.now().toString(36)+Math.random().toString(36).slice(2,7)}
async function loadCustom(){const d=await browser.storage.local.get(['adsecurity_custom_lists','adsecurity_list_priorities']); customProtectionLists=d.adsecurity_custom_lists&&typeof d.adsecurity_custom_lists==='object'?d.adsecurity_custom_lists:{}; listPriorities=d.adsecurity_list_priorities&&typeof d.adsecurity_list_priorities==='object'?d.adsecurity_list_priorities:{}; for(const id of Object.keys(customProtectionLists))if(customProtectionLists[id].tier===undefined)customProtectionLists[id].tier=DEFAULT_LIST_TIER}
async function saveCustom(){await browser.storage.local.set({adsecurity_custom_lists:customProtectionLists})}
async function savePriorities(){await browser.storage.local.set({adsecurity_list_priorities:listPriorities})}
async function addCustomList({name,type,url,rulesText,icon,ownRulesMarker,tier}){const id=genId(), entry={name:name||'Özel Liste',icon:icon||(type==='manual'?'✍️':'🌐'),isCustom:!0,type:type==='manual'?'manual':'remote',author:'Kullanıcı',license:'-',tier:tier!==undefined?tier:DEFAULT_LIST_TIER}; if(ownRulesMarker)entry.ownRulesMarker=ownRulesMarker; if(entry.type==='manual')entry.rulesText=rulesText||''; else{if(!url)throw new Error('URL gerekli'); entry.urls=[url]; entry.supportURL=url} customProtectionLists[id]=entry; await saveCustom(); if(ownRulesMarker){activeProtectionLists.add(id); await saveSettings(); await rebuildFilters()} return id}
async function updateCustomList(id,{name,url,rulesText,icon,tier}){const e=customProtectionLists[id]; if(!e)throw new Error('Liste bulunamadı'); if(name!==undefined)e.name=name; if(icon!==undefined)e.icon=icon; if(tier!==undefined)e.tier=tier; if(e.type==='manual'&&rulesText!==undefined)e.rulesText=rulesText; if(e.type==='remote'&&url!==undefined){e.urls=[url]; e.supportURL=url} await saveCustom(); await rebuildFilters()}
async function removeCustomList(id){delete customProtectionLists[id]; delete listPriorities[id]; activeProtectionLists.delete(id); await saveCustom(); await savePriorities(); await saveSettings(); await browser.storage.local.remove(['adsecurity_filter_cache_'+id,'adsecurity_filter_updated_'+id]); await rebuildFilters()}
async function setListPriorities(p){listPriorities={...p}; await savePriorities(); await rebuildFilters()}

// ============== AYARLAR ==============
async function loadSettings(){const d=await browser.storage.local.get(['adsecurity_protection_lists','adsecurity_advanced_mode','adsecurity_list_tiers']); activeProtectionLists=Array.isArray(d.adsecurity_protection_lists)?new Set(d.adsecurity_protection_lists):new Set(Object.keys(PROTECTION_LISTS).filter(id=>PROTECTION_LISTS[id].defaultOn===!0)); advancedModeEnabled=d.adsecurity_advanced_mode||!1; if(d.adsecurity_list_tiers)for(const [id,t] of Object.entries(d.adsecurity_list_tiers))if(PROTECTION_LISTS[id])PROTECTION_LISTS[id].tier=t}
async function saveSettings(){await browser.storage.local.set({adsecurity_protection_lists:[...activeProtectionLists],adsecurity_advanced_mode:advancedModeEnabled})}
async function loadDefinitions(){try{const r=await fetch(browser.runtime.getURL('filtre.json')); if(r.ok){PROTECTION_LISTS=await r.json(); for(const id of Object.keys(PROTECTION_LISTS)){if(PROTECTION_LISTS[id].tier===undefined)PROTECTION_LISTS[id].tier=id==='ublock-quick-fixes'||id.includes('fixes')?TIER.FIXES:DEFAULT_LIST_TIER}}}catch(e){PROTECTION_LISTS={}}}

// ============== TİER / ÖNCELİK ==============
function getPriority(id){if(id==='ublock-quick-fixes'||id.includes('fixes'))return TIER.FIXES; if(listPriorities[id]!==undefined)return listPriorities[id]; if(customProtectionLists[id]?.tier!==undefined)return customProtectionLists[id].tier; if(PROTECTION_LISTS[id]?.tier!==undefined)return PROTECTION_LISTS[id].tier; return DEFAULT_LIST_TIER}
function getListTier(id){return getPriority(id)}
async function updateListTier(id,tier){if(id in customProtectionLists){customProtectionLists[id].tier=tier; await saveCustom(); await rebuildFilters(); return!0} if(id in PROTECTION_LISTS){const s=await browser.storage.local.get('adsecurity_list_tiers')||{}; if(!s.adsecurity_list_tiers)s.adsecurity_list_tiers={}; s.adsecurity_list_tiers[id]=tier; await browser.storage.local.set(s); PROTECTION_LISTS[id].tier=tier; await rebuildFilters(); return!0} return!1}
async function getAdvancedMode(){return advancedModeEnabled}
async function setAdvancedMode(e){advancedModeEnabled=e; await browser.storage.local.set({adsecurity_advanced_mode:e}); return advancedModeEnabled}

// ============== LİSTE SIRASI & İNDİRME ==============
function getOrderedLists(){const all={...PROTECTION_LISTS,...customProtectionLists}, ids=Object.keys(all).filter(id=>activeProtectionLists.has(id)); const fixes=ids.filter(id=>getPriority(id)===TIER.FIXES), normal=ids.filter(id=>getPriority(id)!==TIER.FIXES).sort((a,b)=>getPriority(a)-getPriority(b)); return [...normal,...fixes].map(id=>({id,list:all[id]}))}
async function fetchList(urls){for(const u of urls)try{const r=await fetch(u,{cache:'no-cache'}); if(r.ok)return await r.text()}catch(e){continue}return null}

// ============== İNDİRME-ZAMANI TEMİZLİK ==============
// Ham liste metni DNR/MV3 dönüşümüne (FilterRule parse, TieredRuleProcessor,
// filterRulesToDnr) girmeden ÖNCE burada temizlenir: hosts->adblock çevirisi +
// engellenen TLD + anlamsız kurallar + birebir eşleşenler (lib/hosts.js).
// Önbelleğe SADECE temiz metin yazılır; ham metin hiç saklanmaz.
// Çalışma-zamanı elekleri (parseFilterListToArray, filterRulesToDnr)
// güvenlik ağıdır; girdi temiz olduğundan pratikte tetiklenmez.
function sanitizeDownloadedList(rawText){
    try{
        if(typeof globalThis.AdSecHosts!=='undefined'&&globalThis.AdSecHosts.sanitizeListText){
            return globalThis.AdSecHosts.sanitizeListText(rawText).text;
        }
    }catch(e){}
    return rawText||'';
}

// ============== SCRIPLET PARSE CACHE ==============
const scriptletParseCache = new Map();

// ============== SCRIPLET PARSE FONKSİYONLARI ==============
// Tarayıcı makinesi: tırnak, regex-literal ve kaçış-duyarlı.
// Regex argümanlardaki (özellikle `\(`, `\)` gibi kaçışlı) parantezler
// saf sayaçları bozup tüm kuralı çöpe atıyordu.
function isScriptletRegexStart(s, i) {
    let j = i - 1;
    while (j >= 0 && /\s/.test(s[j])) j--;
    if (j < 0) return true;
    return '([{=:,!&|?;'.includes(s[j]);
}
// Ayırıcı içindeki karşılığı: devam eden argüman parçasının sonunda değer-başı kontrolü.
// Eski `current.trim() === ''` sezgiselinin üst kümesidir (boşluk-dışı aynı sonuç).
function isScriptletRegexStartToken(current) {
    const t = current.replace(/\s+$/, '');
    if (t === '') return true;
    return '([{=:,!&|?;'.includes(t[t.length - 1]);
}
// `/` karakteri gerçekten bir regex-literal açıyor mu? Kapanış `/`
// yoksa (ör. liste yazarının yazdığı düz `player?` filtresi) düz metindir.
// uBO da kapanışsız `/` desenini regex saymaz.
function hasClosingSlash(s, i) {
    let inClass = false;
    for (let j = i + 1; j < s.length; j++) {
        const ch = s[j];
        if (ch === '\\') { j++; continue; }
        if (ch === '[') { inClass = true; continue; }
        if (ch === ']' && inClass) { inClass = false; continue; }
        if (ch === '/' && !inClass) return true;
    }
    return false;
}
function findMatchingParen(s, openIdx) {
    let depth = 0, q = null, inRe = false;
    for (let i = openIdx; i < s.length; i++) {
        const ch = s[i];
        if (inRe) {
            if (ch === '\\') { i++; continue; }
            if (ch === '/') {
                while (i + 1 < s.length && /[gimsuy]/.test(s[i + 1])) i++;
                inRe = false;
            }
            continue;
        }
        if (q) {
            if (ch === '\\') { i++; continue; }
            if (ch === q) q = null;
            continue;
        }
        if (ch === '"' || ch === "'") { q = ch; continue; }
        if (ch === '\\') { i++; continue; }
        if (ch === '/' && isScriptletRegexStart(s, i) && hasClosingSlash(s, i)) { inRe = true; continue; }
        if (ch === '(') depth++;
        else if (ch === ')') { depth--; if (depth === 0) return i; }
    }
    return -1;
}
/**
 * Ham scriptlet kodunu { name, args } şeklinde ayrıştırır.
 * trusted- prefix'ini korur.
 * Hata durumunda null döndürür, hata loglamaz.
 */
function parseScriptletCode(rawCode) {
    if (!rawCode || typeof rawCode !== 'string') return null;
    const cached = scriptletParseCache.get(rawCode);
    if (cached !== undefined) return cached;

    try {
        let code = rawCode.trim().replace(/;$/, '');
        // Dış sarmalayıcı katmanlarını soy: `(...)` — aç parantezin eşleşen
        // kapanışı kodun sonundaysa (tırnak/regex/kaçış-duyarlı tarama ile).
        // Kör `replace(/\)+$/, '')` kapanışı silip argümanları yok ediyordu;
        // saf sayaç ise regex içindeki parantezlere takılıp kuralı çöpe atıyordu.
        for (;;) {
            if (!(code.length > 1 && code[0] === '(')) break;
            if (findMatchingParen(code, 0) === code.length - 1) { code = code.slice(1, -1).trim(); continue; }
            break;
        }

        const nameMatch = code.match(/^(trusted-[\w.-]+|[\w.-]+)/);
        if (!nameMatch) {
            scriptletParseCache.set(rawCode, null);
            return null;
        }

        const name = nameMatch[1];
        const remaining = code.slice(name.length).trim();

        if (remaining === '') {
            const result = { name, args: [] };
            scriptletParseCache.set(rawCode, result);
            return result;
        }

        // `ad(...)` formu: içerik dengeli çıkarılır. Parantezsiz
        // `ad, arg1, arg2` formunda ise addan sonraki İLK virgül ayraçtır,
        // argüman değil (alınmazsa tüm argümanlar bir kayar).
        let argsStr = null;
        const rt = remaining.trim();
        if (rt === '()') {
            const result = { name, args: [] };
            scriptletParseCache.set(rawCode, result);
            return result;
        } else if (rt[0] === '(') {
            const close = findMatchingParen(rt, 0);
            if (close !== -1) argsStr = rt.slice(1, close);
            else argsStr = rt;
        } else {
            argsStr = remaining.replace(/^\s*,/, '');
        }

        if (argsStr.trim() === '') {
            const result = { name, args: [] };
            scriptletParseCache.set(rawCode, result);
            return result;
        }

        const args = splitScriptletArgs(argsStr);
        const result = { name, args };
        scriptletParseCache.set(rawCode, result);
        return result;
    } catch (e) {
        scriptletParseCache.set(rawCode, null);
        return null;
    }
}

function splitScriptletArgs(str) {
    if (str === undefined || str === null) return [];
    try {
        if (typeof str !== 'string') return [];
        const args = [];
        let current = '';
        let inQuote = false;
        let quoteChar = '';
        let inRegex = false;
        let parenDepth = 0;
        let bracketDepth = 0;
        let braceDepth = 0;

        for (let i = 0; i < str.length; i++) {
            const ch = str[i];

            if (inRegex) {
                current += ch;
                if (ch === '\\') { i++; current += str[i] || ''; continue; }
                if (ch === '/') {while (i + 1 < str.length && /[gimsuy]/.test(str[i + 1])) {i++; current += str[i];}inRegex = false;}
                continue;
            }

            if (inQuote) {
                if (ch === '\\') { i++; current += str[i] || ''; continue; }
                if (ch === quoteChar) { inQuote = false; }
                current += ch;
                continue;
            }

            if (ch === '"' || ch === "'") {
                inQuote = true;
                quoteChar = ch;
                current += ch;
                continue;
            }

            // Normal modda kaçış: `\(`, `\)`, `\,` özel anlam taşımaz,
            // iki karakter birlikte korunur (bölme/parantez sayımı etkilenmez).
            if (ch === '\\') { current += ch + (str[i + 1] || ''); i++; continue; }

            if (ch === '/' && isScriptletRegexStartToken(current) && hasClosingSlash(str, i)) {
                inRegex = true;
                current += ch;
                continue;
            }

            if (ch === '(') { parenDepth++; current += ch; continue; }
            if (ch === ')') { if (parenDepth > 0) { parenDepth--; current += ch; continue; } }
            if (ch === '[') { bracketDepth++; current += ch; continue; }
            if (ch === ']') { if (bracketDepth > 0) { bracketDepth--; current += ch; continue; } }
            if (ch === '{') { braceDepth++; current += ch; continue; }
            if (ch === '}') { if (braceDepth > 0) { braceDepth--; current += ch; continue; } }

            if (ch === ',' && parenDepth === 0 && bracketDepth === 0 && braceDepth === 0) {
                args.push(current.trim());
                current = '';
                continue;
            }
            current += ch;
        }
        if (current.trim()) args.push(current.trim());
        return args.map(arg => {
            if (arg.length >= 2 &&((arg[0] === '"' && arg[arg.length - 1] === '"') || (arg[0] === "'" && arg[arg.length - 1] === "'"))) {return arg.slice(1, -1);}
            if (arg.startsWith('/') && arg.lastIndexOf('/') > 0) {return arg;}
            return arg;
        });
    } catch (e) {return [];}
}

// ============== YEREL (STATİK) vs UZAK (DİNAMİK) DNR KAYNAĞI ==============
// Ayrım tek alana bakar: `filtre.json` içinde `localDnrRuleset` olan liste
// LOKALDİR (koruma manifest'teki statik dnr-rules/*.json kopyasından gelir,
// uzaktan indirilmez, dinamik havuza girmez). `localDnrRuleset` OLMAYAN her
// liste UZAKTIR (`urls` içindeki raw linklerden çekilir, dinamik kurallara
// çevrilir). Liste açılıp kapatıldıkça ilgili statik ruleset
// enable/disable edilir.
async function syncStaticDnrRulesets(){
    try{
        const dnr = (browser.declarativeNetRequest) ||
            (typeof globalThis.chrome !== 'undefined' && globalThis.chrome.declarativeNetRequest) || null;
        if(!dnr || !dnr.updateEnabledRulesets) return;
        const all = {...PROTECTION_LISTS, ...customProtectionLists};
        const enable = [], disable = [];
        for(const [id, list] of Object.entries(all)){
            if(!list || !list.localDnrRuleset) continue;
            // Bir liste birden fazla statik ruleset'e bölünebilir
            // (dosya başına 30000 kural limiti): dizi de desteklenir.
            const rids = Array.isArray(list.localDnrRuleset) ? list.localDnrRuleset : [list.localDnrRuleset];
            for(const rid of rids) (activeProtectionLists.has(id) ? enable : disable).push(rid);
        }
        if(!enable.length && !disable.length) return;
        // Bilinmeyen id verilirse API toplu çağrıda hata fırlatır; tek tek dene.
        if(enable.length) try{ await dnr.updateEnabledRulesets({enableRulesetIds: enable}); }catch(e){
            for(const rid of enable) try{ await dnr.updateEnabledRulesets({enableRulesetIds: [rid]}); }catch(e2){}
        }
        if(disable.length) try{ await dnr.updateEnabledRulesets({disableRulesetIds: disable}); }catch(e){
            for(const rid of disable) try{ await dnr.updateEnabledRulesets({disableRulesetIds: [rid]}); }catch(e2){}
        }
    }catch(e){}
}

// ============== FİLTRELERİ YENİDEN İNŞA ET ==============
async function rebuildFilters(force=!1){
    filterRules.length=0; cosmeticRules.length=0; scriptletRules.length=0; popupRules.length=0;
    webRequestHandler.rules.csp.length=0; webRequestHandler.rules.redirect.length=0; webRequestHandler.rules.removeParam.length=0;
    webRequestHandler.rules.cookie.length=0; webRequestHandler.rules.replace.length=0; webRequestHandler.rules.uriTransform.length=0;
    badFilterTexts.clear();
    scriptletParseCache.clear();
    const tp=new TieredRuleProcessor, fp=new QuickFixProcessor; tp.setFixesProcessor(fp);
    const failed=[];
    const ordered = getOrderedLists();
    // Metin yükleme PARALEL (ağ beklemesi üst üste binmez); parse sırası
    // tier-dizilimini korur (aşağıdaki sıralı döngü).
    const loaded = await Promise.all(ordered.map(async ({id,list}) => {
        // LOKAL liste: uzaktan ÇEKİLMEZ; dnr-rules/*.json statik kuralları
        // kullanılır (durum senkronu: syncStaticDnrRulesets). Dinamik havuza
        // kural eklenmez. Eski uzaktan kopya önbelleği varsa sil.
        // UZAK liste: else dalında raw linkten çekilir -> dinamik kural olur.
        if(list.localDnrRuleset){
            try{ await browser.storage.local.remove(['adsecurity_filter_cache_'+id,'adsecurity_filter_updated_'+id]); }catch(e){}
            return { id, tier: getPriority(id), text: null };
        }
        const tier=getPriority(id); let text=null;
        if(list.isCustom&&list.type==='manual')text=sanitizeDownloadedList(list.rulesText||'');
        else{const ck='adsecurity_filter_cache_'+id, uk='adsecurity_filter_updated_'+id, s=await browser.storage.local.get([ck,uk]); text=s[ck]||null; const last=s[uk]||0, stale=force||Date.now()-last>216e5;
            // Önbellekteki eski (ham) kopya ilk okumada temizlenip geri yazılır;
            // sonrasında önbellekte hep temiz metin durur (migrasyon).
            if(text){const cl=sanitizeDownloadedList(text); if(cl!==text){text=cl; try{await browser.storage.local.set({[ck]:text})}catch(e){}}}
            // Taze indirme: ham metin hiç saklanmaz, temizlenmiş hali yazılır.
            if(!text||stale){const f=await fetchList(list.urls||[]); if(f){text=sanitizeDownloadedList(f); await browser.storage.local.set({[ck]:text,[uk]:Date.now()})}else if(force)failed.push(list.name||id)}}
        return { id, tier, text };
    }));
    for(const {id,tier,text} of loaded){
        if(!text)continue;
        // preSanitized: indirme-anı temizliği yapıldı; çift normalize yok,
        // parçalı parse (SW 30sn kill riskine karşı verimli).
        const rules=await parseFilterListToArray(text,id,true);
        for(const r of rules){if(r.isBadFilter){if(tier===TIER.FIXES)tp.addRule(r,tier,id,'block'); else badFilterTexts.add(r.ruleText.replace(/\$badfilter/,'').trim()); continue} if(r.isCosmetic&&r.cosmeticSelector)tp.addRule(r,tier,id,'cosmetic'); else if(r.isScriptlet)tp.addRule(r,tier,id,'scriptlet'); else if(r.isCSP)tp.addRule(r,tier,id,'csp'); else if(r.isRedirect)tp.addRule(r,tier,id,'redirect'); else if(r.isRemoveParam)tp.addRule(r,tier,id,'removeparam'); else if(r.isCookie)tp.addRule(r,tier,id,'cookie'); else if(r.isPopup)tp.addRule(r,tier,id,'popup'); else if(r.isReplace)tp.addRule(r,tier,id,'replace'); else if(r.isUriTransform)tp.addRule(r,tier,id,'uritransform'); else tp.addRule(r,tier,id,'block')}
    }
    tp.processAll();
    const cats=['block','cosmetic','scriptlet','popup','csp','redirect','removeparam','cookie','replace','uritransform'];
    const targets=[filterRules,cosmeticRules,scriptletRules,popupRules,webRequestHandler.rules.csp,webRequestHandler.rules.redirect,webRequestHandler.rules.removeParam,webRequestHandler.rules.cookie,webRequestHandler.rules.replace,webRequestHandler.rules.uriTransform];
    for(let i=0;i<cats.length;i++){targets[i].push(...tp.getResolved(cats[i]))}

    // Scriptlet kurallarını parse et
    const parsedScriptlets = [];
    for (const r of scriptletRules) {
        if (!r.scriptletCode) continue;
        const parsed = parseScriptletCode(r.scriptletCode);
        if (!parsed) {badFilterTexts.add(r.ruleText);continue;}
        r.scriptletName = parsed.name;
        r.scriptletArgs = parsed.args;
        parsedScriptlets.push(r);
    }
    scriptletRules.length = 0;
    scriptletRules.push(...parsedScriptlets);

    webRequestHandler.setTierProcessor(tp);
    finalizeBadFilters();
    broadcastRules();
    webRequestHandler.updateRules({block:filterRules,csp:webRequestHandler.rules.csp,redirect:webRequestHandler.rules.redirect,removeParam:webRequestHandler.rules.removeParam,cookie:webRequestHandler.rules.cookie,replace:webRequestHandler.rules.replace,uriTransform:webRequestHandler.rules.uriTransform});
    // MV3: ağ engelleme DNR dinamik kurallarıyla uygulanır.
    try{ if(typeof DnrManager!=='undefined'&&DnrManager.syncFromRules) await DnrManager.syncFromRules(); }catch(e){}
    // Yerel DNR kopyası olan listelerin statik ruleset durumunu eşitle.
    try{ await syncStaticDnrRulesets(); }catch(e){}
    if(force&&failed.length)throw new Error('Güncellenemedi: '+failed.join(', '));
}

// ============== ALARMLAR ==============
// MV3: setInterval YOK (SW uyur); periyodik işler chrome.alarms ile.
try{
if(browser.alarms && browser.alarms.onAlarm)
browser.alarms.onAlarm.addListener(a=>{
    if(a.name==='adsecurity_filters_refresh')rebuildFilters();
    // core.js setup() bu alarmı kurar; SW uyansa bile cache şişmez.
    if(a.name==='adsecurity_cache_clear'){try{webRequestHandler.clearCache()}catch(e){}}
});
if(browser.alarms && browser.alarms.create)
browser.alarms.create('adsecurity_filters_refresh',{periodInMinutes:360});
}catch(e){}

// ============== PUBLIC API ==============
// MV3 service worker'da `window` yoktur; API globalThis'e asılır.
globalThis.AdSecurity={
    get PROTECTION_LISTS(){return PROTECTION_LISTS},
    FILTER_TIERS:TIER,
    TIER_NAMES:TIER.NAMES,
    getState:()=>({protectionLists:[...activeProtectionLists],advancedMode:advancedModeEnabled}),
    getAvailableLists:()=>({...PROTECTION_LISTS,...customProtectionLists}),
    getListPriorities:()=>{const all={...PROTECTION_LISTS,...customProtectionLists}, out={}; for(const id of Object.keys(all))out[id]=getPriority(id); return out},
    getListTier,
    setProtectionLists:async ids=>{activeProtectionLists=new Set(ids); await saveSettings(); await rebuildFilters()},
    getActiveProtectionLists:()=>[...activeProtectionLists],
    refreshProtectionLists:async()=>{const err=[]; try{await rebuildFilters(!0)}catch(e){err.push(e?.message||String(e))} try{await loadPSL(!0)}catch(e){err.push(e?.message||String(e))} if(err.length)throw new Error(err.join(' | '))},
    refreshPublicSuffixList:async()=>{await browser.storage.local.remove('adsecurity_psl_updated'); await loadPSL()},
    addCustomList,updateCustomList,removeCustomList,setListPriorities,updateListTier,getAdvancedMode,setAdvancedMode
};

try{
if(browser.runtime && browser.runtime.onMessage)
browser.runtime.onMessage.addListener((msg,_,sr)=>{if(!msg||msg.namespace!=='adsecurity')return; const a=msg.action; const asyncFn=async()=>{try{switch(a){case'getState':sr(globalThis.AdSecurity.getState()); return; case'getProtectionLists':sr({active:globalThis.AdSecurity.getActiveProtectionLists(),available:globalThis.AdSecurity.getAvailableLists(),priorities:globalThis.AdSecurity.getListPriorities(),tiers:globalThis.AdSecurity.getListPriorities(),tierNames:TIER.NAMES,advancedMode:advancedModeEnabled}); return; case'setProtectionLists':await globalThis.AdSecurity.setProtectionLists(msg.lists); sr({ok:!0}); return; case'refreshProtectionLists':await globalThis.AdSecurity.refreshProtectionLists(); sr({ok:!0}); return; case'addCustomList':{const id=await addCustomList(msg.data||{}); sr({ok:!0,id}); return} case'updateCustomList':await updateCustomList(msg.id,msg.data||{}); sr({ok:!0}); return; case'removeCustomList':await removeCustomList(msg.id); sr({ok:!0}); return; case'setListPriorities':await setListPriorities(msg.priorities||{}); sr({ok:!0}); return; case'updateListTier':await updateListTier(msg.id,msg.tier); sr({ok:!0}); return; case'setAdvancedMode':await setAdvancedMode(msg.enabled); sr({ok:!0,enabled:advancedModeEnabled}); return; case'getAdvancedMode':sr({enabled:advancedModeEnabled}); return;
case'getContentRules':sr({ok:!0,rules:buildContentRulesPayload()}); return;
default:sr({})}}catch(e){sr({ok:!1,error:String(e?.message||e)})}}; asyncFn(); return!0});
}catch(e){}

// ============== BAŞLATMA (MV3) ==============
// Service worker her uyanışta bu zincir çalışır; global durum storage'dan
// yeniden kurulur (SW belleği kalıcı değildir). onStartup/onInstalled
// dinleyicileri background.js tarafından kurulur; burada boot() paylaşılır.
let _bootPromise = null;
function bootAdSecurity(){
    if(_bootPromise) return _bootPromise;
    _bootPromise = loadDefinitions().then(()=>loadSettings()).then(async()=>{
        await loadCustom(); await loadDisabledSites(); await loadPSL(); await rebuildFilters(); webRequestHandler.setup();
        // setup() sonrası session kurallarını (TLD/disabled) kesin yaz.
        try{ if(typeof DnrManager!=='undefined'&&DnrManager.syncFromRules) await DnrManager.syncFromRules(); }catch(e){}
        try{ if(typeof refreshTabHostnames==='function') refreshTabHostnames(); }catch(e){}
    }).catch(e=>{ _bootPromise = null; throw e; });
    return _bootPromise;
}
globalThis.AdSecBoot = bootAdSecurity;
// SW uyanışında otomatik önyükleme; API yoksa/başarısızsa sessizce bırak
// (sonraki uyanışta _bootPromise sıfırlandığı için yeniden denenecek).
try{ bootAdSecurity().catch(e=>console.warn('[AdSecurity] boot:', (e&&e.message)||e)); }catch(e){}