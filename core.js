'use strict';
// ============== MV3 UYUMLULUK ==============
// MV3 service worker: `browser` (Firefox) yoksa `chrome` kullanılır.
// webRequest blocking YOKTUR; ağ engelleme declarativeNetRequest (DNR)
// dinamik kurallarıyla yapılır (bkz. DnrManager + lib/rule-to-dnr.js).
// AdGuard @adguard/dnr-converter Node tarafında (tools/build-dnr.mjs)
// statik kurallar için kullanılır; SW içinde runtime dönüşüm
// SW-safe dahili çeviriciyle (AdSecDnr) yapılır.
var browser = (typeof globalThis.browser !== 'undefined' && globalThis.browser) ||
    (typeof globalThis.chrome !== 'undefined' && globalThis.chrome) ||
    (typeof browser !== 'undefined' && browser) || {};
// ============== STATIC SABİTLER ==============
const TIER = {LOW: 0,NORMAL: 1,SENIOR: 2,UNRULY: 3,FIXES: 4,
    NAMES: {0:'Alt',1:'Sıradan',2:'Kıdemli',3:'Kural Tanımaz',4:'Fixes'}};
const DEFAULT_LIST_TIER = TIER.NORMAL;

const TYPE_MODIFIERS = ['script','image','stylesheet','object','xmlhttprequest','media','font','websocket','document','popup','main_frame','sub_frame','ping','other','frame','fetch','csp_report'];
const DANGEROUS_SELECTOR_PATTERNS = [/<script/i,/<iframe/i,/javascript:/i,/on\w+\s*=/i,/document\./i,/window\./i,/eval\(/i,/Function\(/i,/setTimeout\(/i,/setInterval\(/i,/innerHTML/i,/outerHTML/i];
const PROCEDURAL_SELECTOR_PATTERN = /:(has-text|has|style|matches-css(?:-before|-after)?|matches-attr|matches-prop|xpath|upward|remove|watch-attrs|min-text-length|if|if-not|min-outer-width|max-outer-width|min-outer-height|max-outer-height|others|matches-media)\(/i;

// ============== BLOCKED TLD TAM ENGELLEME ==============
// Bu iki TLD'yi kullanan site/link ne olursa olsun engellenir.
// Filtre-listesi temizliği indirme anında yapılır (lib/hosts.js
// sanitizeListText); buradaki kural-seviyesi elekler kaldırıldı.
// Bu TLD'ler etiketsiz tutulur; hostnameUsesBlockedTLD son etiketi karşılaştırır.
// Kalan kullanım: canlı zorlama (webNavigation).
const BLOCKED_TLDS = new Set(['click','top','mov','zip']);
function hostnameUsesBlockedTLD(h){
    if(!h)return!1;
    const H=String(h).toLowerCase().trim().replace(/^https?:\/\//,'').split('/')[0].split(':')[0].replace(/\.+$/,'');
    if(!H)return!1;
    const labels=H.split('.');
    if(labels.length<2)return!1;
    return BLOCKED_TLDS.has(labels[labels.length-1]);
}

// ============== GLOBAL DEĞİŞKENLER ==============
let activeProtectionLists = new Set(), tabHostnames = {}, disabledSites = new Set();
let pslExactRules = new Set(), pslWildcardRules = new Set(), pslExceptionRules = new Set(), pslLoaded = !1;
let customProtectionLists = {}, listPriorities = {};
let filterRules = [], cosmeticRules = [], scriptletRules = [], popupRules = [], badFilterTexts = new Set();
let PROTECTION_LISTS = {};
let advancedModeEnabled = !1;

// ============== TIERED RULE PROCESSOR ==============
class TieredRuleProcessor {
    constructor() {
        this.tiers = {block:new Map,cosmetic:new Map,scriptlet:new Map,popup:new Map,csp:new Map,redirect:new Map,removeparam:new Map,cookie:new Map,replace:new Map,uritransform:new Map};
        this.masterRules = []; this.masterRulesSet = new Set; this.masterRulesIndex = {byDomain:new Map,generic:[]}; this.masterExceptions = []; this.masterExceptionsIndex = {byDomain:new Map,generic:[]}; this.processed = !1; this.fixesProcessor = null;
    }
    setFixesProcessor(p){this.fixesProcessor=p}
    addRule(r,t,l,c='block'){const m=this.tiers[c]||this.tiers.block;m.has(t)||m.set(t,[]);m.get(t).push({rule:r,listId:l})}
    processAll(){
        if(this.processed)return;
        this.fixesProcessor?.processBadFilters(this);
        for(const c of Object.keys(this.tiers))this.resolveConflicts(c);
        this.masterRules = this.getMasterRules();
        this.masterRulesSet = new Set(this.masterRules);
        this.masterRulesIndex = buildDomainIndex(this.masterRules);
        this.masterExceptions = this.getMasterExceptions();
        this.masterExceptionsIndex = buildDomainIndex(this.masterExceptions);
        this.processed = !0;
    }
    resolveConflicts(cat){
        const map = this.tiers[cat]; if(!map)return;
        const tiers = [...map.keys()].sort((a,b)=>b-a), resolved = [], used = new Map;
        for(const t of tiers){
            const items = map.get(t)||[], isUnruly = t===TIER.UNRULY, isFixes = t===TIER.FIXES;
            for(const it of items){
                const key = this.getKey(it.rule);
                if(isFixes){ if(this.fixesProcessor?.isBadFilter(it.rule)){this.fixesProcessor.markForRemoval(it.rule);continue} resolved.push(it); continue }
                const prev = used.get(key);
                if(prev){
                    if(prev.listId===it.listId){
                        if(it.rule.isException&&!prev.rule.isException){ this.replaceResolved(resolved,prev,it); used.set(key,it) }
                        continue;
                    }
                    if(isUnruly){
                        if(it.rule.isException){ continue }
                        if(!prev.rule.isException){ continue }
                        this.replaceResolved(resolved,prev,it); used.set(key,{...it,isMaster:!0});
                        continue;
                    }
                    continue;
                }
                if(isUnruly){ const entry={...it,isMaster:!0}; resolved.push(entry); used.set(key,entry) }
                else { let hasEx = !1; if(this.fixesProcessor)hasEx=this.fixesProcessor.hasExceptionFor(it.rule); if(!hasEx){resolved.push(it);used.set(key,it)} }
            }
        }
        map.clear();
        map.set(TIER.UNRULY, resolved.filter(r=>r.isMaster));
        map.set(TIER.NORMAL, resolved.filter(r=>!r.isMaster&&!r.isFixes));
    }
    replaceResolved(resolved,oldEntry,newEntry){ const i=resolved.indexOf(oldEntry); if(i!==-1)resolved[i]=newEntry; else resolved.push(newEntry) }
    getKey(r){ if(r.isRegex&&r.regex)return'regex:'+r.regex.source; if(r.isCosmetic&&r.cosmeticSelector)return'cosmetic:'+r.domain+':'+r.cosmeticSelector; if(r.isScriptlet&&r.scriptletCode)return'scriptlet:'+r.domain+':'+r.scriptletCode; let t=r.ruleText||''; if(r.isException&&t.startsWith('@@'))t=t.slice(2); return t }
    getMasterRules(){ const out=[]; for(const c of['block','popup']){for(const it of(this.tiers[c]?.get(TIER.UNRULY)||[]))if(it.isMaster&&!it.rule.isException)out.push(it.rule)} return out }
    getMasterExceptions(){ const out=[]; for(const c of['block','popup']){for(const it of(this.tiers[c]?.get(TIER.UNRULY)||[]))if(it.isMaster&&it.rule.isException)out.push(it.rule)} return out }
    getResolved(cat){ const map=this.tiers[cat]; if(!map)return[]; const out=[]; for(const t of[...map.keys()].sort((a,b)=>b-a))out.push(...(map.get(t)||[]).map(it=>it.rule)); return out }
    isMaster(r){return this.masterRulesSet.has(r)}
}

// ============== QUICK FIX PROCESSOR ==============
class QuickFixProcessor {
    constructor(){
        this.badfilterPatterns=new Map;
        this.removedRules=new Set;
        this.badfilterCache=new Map;
    }
    processBadFilters(tp){
        for(const cat of ['block','cosmetic','scriptlet','popup']){
            const items = tp.tiers[cat]?.get(TIER.FIXES)||[];
            for(const it of items){
                if(this.isBadFilter(it.rule)){
                    const p=this.extract(it.rule);
                    if(p){
                        this.badfilterPatterns.set(p, it.rule);
                        this.badfilterCache.set(p, true);
                    }
                }
            }
        }
        this.apply(tp)
    }
    isBadFilter(r){
        if(!r)return false;
        if(r.isBadFilter)return true;
        if(r.ruleText && r.ruleText.includes('$badfilter'))return true;
        const key = this.extract(r);
        if(key && this.badfilterCache.has(key))return true;
        return false;
    }
    extract(r){
        if(!r)return null;
        let t = r.ruleText||'';
        t = t.replace(/\$badfilter/g, '').trim();
        t = t.replace(/^@@/, '');
        if(t.startsWith('||')){
            const parts = t.split('/');
            if(parts.length > 1){
                t = parts.slice(1).join('/');
            }
        }
        return t;
    }
    apply(tp){
        for(const cat of Object.keys(tp.tiers)){
            const map=tp.tiers[cat];
            if(!map)continue;
            for(const t of map.keys()){
                if(t===TIER.FIXES)continue;
                const items=map.get(t)||[], filtered=[];
                for(const it of items){
                    const p=this.extract(it.rule);
                    if(p&&this.badfilterPatterns.has(p)){
                        this.removedRules.add(it.rule);
                        console.log('[AdSecurity] Badfilter applied:', p);
                        continue;
                    }
                    filtered.push(it);
                }
                map.set(t, filtered);
            }
        }
    }
    hasExceptionFor(r){if(!r)return!1;const p=this.extract(r);return!!p&&(this.removedRules.has(r)||this.badfilterPatterns.has(p))}
    markForRemoval(r){this.removedRules.add(r)}
}

// ============== WEBREQUEST HANDLER ==============
class WebRequestHandler {
    constructor(){
        this.rules = {block:[],csp:[],redirect:[],removeParam:[],cookie:[],replace:[],uriTransform:[],importantExceptions:[],importantBlocks:[],exceptions:[],blocks:[],genericBlockRules:[],genericBlockOverrides:[],importantExceptionsByDomain:{byDomain:new Map,generic:[]},importantBlocksByDomain:{byDomain:new Map,generic:[]},exceptionsByDomain:{byDomain:new Map,generic:[]},blocksByDomain:{byDomain:new Map,generic:[]},redirectByDomain:{byDomain:new Map,generic:[]},mediaBlocks:{byDomain:new Map,generic:[]},importantMediaBlocks:{byDomain:new Map,generic:[]}};
        this.isInitialized=!1; this.urlCache=new Map; this.cacheTimestamps=new Map; this.MAX_CACHE_SIZE=500; this.CACHE_TTL=6e4; this.tierProcessor=null;
    }
    setup(){
        // MV3: ağ engelleme DNR dinamik + statik kurallarıyla yapılır
        // (DnrManager.syncFromRules + syncStaticDnrRulesets). webRequest
        // blocking dinleyicisi yoktur. Burada sadece periyodik cache
        // temizliği alarmı kurulur.
        if(this.isInitialized)return;
        try{
            if(browser.alarms && browser.alarms.create){
                browser.alarms.create('adsecurity_cache_clear',{periodInMinutes:1});
            }
        }catch(e){}
        this.isInitialized=!0
    }
    setTierProcessor(p){this.tierProcessor=p}
    clearCache(){const n=Date.now(); for(const [k,t] of this.cacheTimestamps)if(n-t>this.CACHE_TTL){this.urlCache.delete(k);this.cacheTimestamps.delete(k)} if(this.urlCache.size>this.MAX_CACHE_SIZE){this.urlCache.clear();this.cacheTimestamps.clear()} }
    parseUrl(u){const c=this.urlCache.get(u); if(c!==undefined)return c; try{const p=new URL(u); this.urlCache.set(u,p); this.cacheTimestamps.set(u,Date.now()); return p}catch(e){return null}}
    updateRules(rules){
        const block=rules.block||[], impEx=[], impBl=[], ex=[], bl=[], genBl=[], genOv=[];
        for(const r of block){if(r.isGenericBlock){if(r.isException)genOv.push(r);else genBl.push(r); continue} if(r.isImportant){(r.isException?impEx:impBl).push(r)}else{(r.isException?ex:bl).push(r)}}
        this.rules={block,importantExceptions:impEx,importantBlocks:impBl,exceptions:ex,blocks:bl,genericBlockRules:genBl,genericBlockOverrides:genOv,importantExceptionsByDomain:buildDomainIndex(impEx),importantBlocksByDomain:buildDomainIndex(impBl),exceptionsByDomain:buildDomainIndex(ex),blocksByDomain:buildDomainIndex(bl),csp:rules.csp||[],redirect:rules.redirect||[],removeParam:rules.removeParam||[],cookie:rules.cookie||[],replace:rules.replace||[],uriTransform:rules.uriTransform||[],
        redirectByDomain:buildDomainIndex(rules.redirect||[]),
        mediaBlocks:buildDomainIndex((rules.block||[]).filter(r => r.isMedia || r.modifiers?.media === true)),
        importantMediaBlocks:buildDomainIndex((rules.block||[]).filter(r => (r.isMedia || r.modifiers?.media === true) && r.isImportant))}
    }
}

// DNR kural seti parmak izi (id + priority karması). Her SW uyanışında
// tabloyu silip yeniden yazmak pahalıdır; iz aynıysa API çağrıları atlanır.
function fingerprintRules(rules){let h=0; for(const r of (rules||[])){h=(((h*31)>>>0)+(((r&&r.id)>>>0)))>>>0; h=(((h*31)>>>0)+(((r&&r.priority)>>>0)))>>>0} return h.toString(36)}

// ============== DNR MANAGER (MV3) ==============
// Filtre motorundaki block/allow kurallarını declarativeNetRequest
// dinamik kurallarına yazar. Kaynak: lib/rule-to-dnr.js (SW-safe).
// Statik/ön-hesaplı kurallar için tools/build-dnr.mjs
// (klasördeki @adguard/dnr-converter) kullanılır.
//
// TIER3 KORUMASI: Tier3 (UNRULY) bir filtrenin engelleme kuralı, kendi
// filtresi HARİÇ hiçbir filtrenin (diğer Tier3'ler dahil) @@ kuralıyla
// ezilemez. Aynı-metin çakışmalar resolveConflicts'te çözülür (yabancı @@
// düşer, kendi @@ kazanır); farklı-metin çakışmalar DNR öncelik
// bantlarıyla çözülür (master block 200000 > yabancı allow 100001 >
// ... > kendi @@ 300000 en üstte). Bkz. collectMasterInfo + DNR_PRIORITY.
const DnrManager = {
    MAX_DYNAMIC_RULES: 4500,
    // Engellenen TLD'ler için oturum kuralı kimlikleri (1..100 ayrılmıştır).
    RESERVED_IDS: 100,
    async getDnr(){
        const dnr = (browser.declarativeNetRequest) ||
            (typeof chrome !== 'undefined' && chrome.declarativeNetRequest) || null;
        return dnr || null;
    },
    blockedTldSessionRules(){
        // .click/.top/.mov/.zip: istisnasız engelle (session kuralları, öncelikli).
        // DNR urlFilter sözdizimi: '||*.tld^' geçersizdir, '*://*.tld/*' kullanılır.
        const tlds = [...BLOCKED_TLDS].map(t => String(t).replace(/^\./, ''));
        return tlds.map((tld, i) => ({
            id: i + 1,
            priority: 1000000,
            action: { type: 'block' },
            condition: { urlFilter: '*://*.' + tld + '/*', resourceTypes: ['main_frame'] },
        }));
    },
    disabledSiteAllowRules(){
        // Devre dışı sitelerde DNR engellemesini geri çek (yüksek öncelikli allow).
        // DNR koşulu urlFilter olmadan geçersizdir; her host ayrı kuraldır.
        const hosts = [...disabledSites].slice(0, 900);
        return hosts.map((h, i) => ({
            id: this.RESERVED_IDS + 1 + i,
            priority: 999999,
            action: { type: 'allowAllRequests' },
            condition: { urlFilter: '*://*/*', initiatorDomains: [String(h).toLowerCase()] },
        }));
    },
    // Tier3 (UNRULY) engelleme kurallarını topla: kimlik seti + liste bazında
    // hedef domain haritası. Kural: Tier3 bloğu, KENDİ filtresi hariç hiçbir
    // filtrenin @@ kuralıyla ezilemez (öncelik bantları için lib/rule-to-dnr.js).
    collectMasterInfo(){
        const set = new Set(), domainsByList = {};
        try{
            const tp = (typeof webRequestHandler !== 'undefined' && webRequestHandler.tierProcessor) || null;
            const add = (r) => {
                if(!r || r.isException || r.isCosmetic || r.isScriptlet) return;
                set.add(r);
                if(r.listId && r.domain){
                    const d = String(r.domain).toLowerCase().replace(/^\*\./, '').replace(/\.+$/, '');
                    if(d){ (domainsByList[r.listId] || (domainsByList[r.listId] = new Set())).add(d); }
                }
            };
            if(tp){
                for(const r of (tp.masterRules || [])) add(r);
                // Tier3 $redirect / $removeparam da aynı korumayı alır.
                for(const cat of ['redirect', 'removeParam']){
                    const bucket = tp.tiers && tp.tiers[cat] && tp.tiers[cat].get(TIER.UNRULY);
                    if(Array.isArray(bucket)) for(const it of bucket) if(it && it.isMaster && it.rule) add(it.rule);
                }
            }
        }catch(e){}
        return { set, domainsByList };
    },
    async syncFromRules(){
        const dnr = await this.getDnr();
        if(!dnr) return { ok: false, reason: 'no-dnr-api' };
        const conv = (typeof globalThis.AdSecDnr !== 'undefined' && globalThis.AdSecDnr) || null;
        let networkDnr = [], skipped = {};
        if(conv && typeof conv.filterRulesToDnr === 'function'){
            // block + redirect ($redirect) + removeParam ($removeparam) DNR'a
            // çevrilebilir; cosmetic/scriptlet/CSP/cookie/popup çevrilemez.
            // Lokalde statik karşılığı olan listeler bu havuza hiç girmez
            // (rebuildFilters onları atlar); uzak/raw listeler dinamik olur.
            // Girdi indirme anında temizlenmiştir (sanitizeListText); burada
            // ek TLD/duplicate-metni eleği yoktur.
            const wr = (typeof webRequestHandler !== 'undefined' && webRequestHandler.rules) || {};
            let pool = [...(wr.block || []), ...(wr.redirect || []), ...(wr.removeParam || [])];
            if(!pool.length && typeof filterRules !== 'undefined' && filterRules.length) pool = [...filterRules];
            const master = this.collectMasterInfo();
            const res = conv.filterRulesToDnr(pool, { maxRules: this.MAX_DYNAMIC_RULES, masterSet: master.set, masterDomainsByList: master.domainsByList });
            networkDnr = res.rules; skipped = res.skipped;
        }
        // Session kuralları (TLD + disabled-site) ayrı aralıkta tutulur.
        const sessionRules = [...this.blockedTldSessionRules(), ...this.disabledSiteAllowRules()];
        // Göndermeden önce son şema süzgeci: DNR tek geçersiz kuralda çağrının
        // TAMAMINI reddeder. Aksiyon tipi ve koşul asgarisi burada doğrulanır.
        const VALID_ACTIONS = { block: 1, redirect: 1, allow: 1, upgradeScheme: 1, modifyHeaders: 1, allowAllRequests: 1 };
        networkDnr = networkDnr.filter(r => {
            if(!r || typeof r.id !== 'number' || !r.action || !VALID_ACTIONS[r.action.type] || !r.condition) return false;
            if(!r.condition.urlFilter && !r.condition.regexFilter) return false;
            if(r.action.type === 'redirect' && !r.action.redirect) return false;
            return true;
        });
        // Değişmediyse yazma: iz aynıysa get/update çağrıları atlanır.
        const fp = 'd' + networkDnr.length + ':' + fingerprintRules(networkDnr) + '|s' + sessionRules.length + ':' + fingerprintRules(sessionRules);
        try{
            const st = await browser.storage.local.get('adsecurity_dnr_state');
            if(st && st.adsecurity_dnr_state && st.adsecurity_dnr_state.fp === fp && !st.adsecurity_dnr_state.lastDynamicError){
                return { ok: true, unchanged: true, dynamicCount: networkDnr.length, sessionCount: sessionRules.length, skipped };
            }
        }catch(e){}
        let dynamicError = null;
        const pushDynamic = async (rules) => {
            const oldDynamic = await dnr.getDynamicRules().catch(() => []);
            await dnr.updateDynamicRules({
                removeRuleIds: (oldDynamic || []).map(r => r.id),
                addRules: rules,
            });
        };
        try{
            try{
                await pushDynamic(networkDnr);
            }catch(e){
                // RE2 bellek limiti gibi durumlarda regex kurallarını eleyip
                // geri kalan tabloyu yine de yaz (kısmi koruma > sıfır koruma).
                dynamicError = String((e && e.message) || e);
                const noRegex = networkDnr.filter(r => !r.condition.regexFilter);
                if(noRegex.length !== networkDnr.length){ networkDnr = noRegex; await pushDynamic(noRegex); }
                else throw e;
            }
            if(dnr.updateSessionRules){
                const oldSession = await dnr.getSessionRules().catch(() => []);
                await dnr.updateSessionRules({
                    removeRuleIds: (oldSession || []).map(r => r.id),
                    addRules: sessionRules,
                }).catch(() => {});
            }
            try{
                await browser.storage.local.set({
                    adsecurity_dnr_state: {
                        updated: Date.now(),
                        fp,
                        dynamicCount: networkDnr.length,
                        sessionCount: sessionRules.length,
                        skipped,
                        lastDynamicError: dynamicError,
                    },
                });
            }catch(e){}
            return { ok: true, dynamicCount: networkDnr.length, sessionCount: sessionRules.length, skipped };
        }catch(e){
            return { ok: false, reason: String((e && e.message) || e) };
        }
    },
};

// ============== DOMAIN INDEX ==============
function ruleIndexKey(r){if(r.isRegex||!r.domain||r.domain.includes('*'))return null; return r.domain.toLowerCase()}
function buildDomainIndex(rules){const byDomain=new Map, generic=[]; for(const r of rules){const k=ruleIndexKey(r); if(k===null){generic.push(r); continue} let arr=byDomain.get(k); if(!arr){arr=[]; byDomain.set(k,arr)} arr.push(r)} return{byDomain,generic}}
function candidatesForHost(idx,h){const out=idx.generic.slice(); if(!h)return out; const labels=h.split('.'); for(let i=0;i<labels.length-1;i++){const c=labels.slice(i).join('.'); const arr=idx.byDomain.get(c); if(arr)out.push(...arr)} return out}

// ============== WEBREQUEST INSTANCE ==============
const webRequestHandler = new WebRequestHandler();

// ============== TAB HANDLERS ==============
// MV3 service worker uykudan uyanınca sekmeleri yeniden okur.
function refreshTabHostnames(){
    try{
        if(browser.tabs && browser.tabs.query){
            browser.tabs.query({}).then(tabs=>{for(const t of tabs)try{if(t.url)tabHostnames[t.id]=new URL(t.url).hostname}catch(e){}}).catch(()=>{});
        }
    }catch(e){}
}
try{
    if(browser.tabs && browser.tabs.onUpdated) browser.tabs.onUpdated.addListener((id,info,tab)=>{if(tab?.url)try{tabHostnames[id]=new URL(tab.url).hostname}catch(e){}});
    if(browser.tabs && browser.tabs.onRemoved) browser.tabs.onRemoved.addListener(id=>{delete tabHostnames[id]});
}catch(e){}
refreshTabHostnames();

// ============== SITE DISABLE ==============
function isSiteDisabled(h){return!!h&&disabledSites.has(h)}
async function onDisabledSitesChanged(){
    // MV3: devre dışı siteler DNR allowAllRequests ile uygulanır.
    try{ if(typeof DnrManager !== 'undefined' && webRequestHandler.isInitialized) await DnrManager.syncFromRules(); }catch(e){}
}
try{
    if(browser.storage && browser.storage.onChanged) browser.storage.onChanged.addListener((c,a)=>{if(a!=='local')return; if(c.adsecurity_disabled_sites){const v=c.adsecurity_disabled_sites.newValue; disabledSites=new Set(Array.isArray(v)?v:[]); onDisabledSitesChanged()} if(c.adsecurity_advanced_mode)advancedModeEnabled=c.adsecurity_advanced_mode.newValue||!1});
}catch(e){}

// ============== PSL (PARSE) ==============
function parsePSL(t){const exact=new Set,wildcard=new Set,exception=new Set; for(const raw of t.split('\n')){const line=raw.trim(); if(!line||line.startsWith('//'))continue; const token=line.split(/\s+/)[0].toLowerCase(); if(!token)continue; if(token.startsWith('!'))exception.add(token.slice(1)); else if(token.startsWith('*.'))wildcard.add(token.slice(2)); else exact.add(token)} return{exact,wildcard,exception}}
function isPublicSuffix(d){if(!d)return false; if(pslExactRules.has(d)||pslWildcardRules.has(d)||pslExceptionRules.has(d))return true; if(!pslLoaded)return !d.includes('.'); return false}
function getETLD1(h){if(!h)return''; const labels=h.toLowerCase().split('.'); if(labels.length<2)return h; if(!pslLoaded)return labels.slice(-2).join('.'); for(let i=0;i<labels.length;i++){const c=labels.slice(i).join('.'); if(pslExceptionRules.has(c)){const cnt=labels.length-i-1+1; if(cnt>=labels.length)return h; return labels.slice(labels.length-cnt).join('.')}} let best=1; for(let i=0;i<labels.length;i++){const c=labels.slice(i).join('.'), cnt=labels.length-i; if(pslExactRules.has(c)&&cnt>best)best=cnt; if(i+1<=labels.length){const wb=labels.slice(i+1).join('.'); if(pslWildcardRules.has(wb)&&cnt>best)best=cnt}} const cnt=best+1; if(cnt>=labels.length)return h; return labels.slice(labels.length-cnt).join('.')}
function domainMatches(d,h){if(!d||!h)return!1; const D=d.toLowerCase(), H=h.toLowerCase(); if(D.startsWith('*.')){const b=D.slice(2); return H===b||H.endsWith('.'+b)} return H===D||H.endsWith('.'+D)}

// ============== SAME-SITE (eTLD+1) ==============
function isSameSite(rh,ph){if(!rh||!ph)return!1; return getETLD1(rh)===getETLD1(ph)}

// ============== TİP YARDIMCILARI ==============
const REQUEST_TYPE_GROUPS={document:new Set(['document','main_frame']),subdocument:new Set(['subdocument','sub_frame','frame'])};
function requestTypeMatchesModifier(rt,mod){if(!rt||!mod)return!1; if(REQUEST_TYPE_GROUPS.document.has(mod))return REQUEST_TYPE_GROUPS.document.has(rt); if(REQUEST_TYPE_GROUPS.subdocument.has(mod))return REQUEST_TYPE_GROUPS.subdocument.has(rt); return rt===mod}
function parseAdGuardScriptletCode(code){const t=(code||'').trim(); if(/^#+[\w.[\]()>^~="':,+-]/.test(t)&&t.includes('{'))return'inject-css, '+JSON.stringify(t); return t}

// ============== FILTER RULE ==============
function parseCosmeticDomains(raw){if(!raw)return[]; return raw.split(',').map(t=>t.trim()).filter(Boolean).map(t=>t.startsWith('~')?{domain:t.slice(1),negated:!0}:{domain:t,negated:!1})}
class FilterRule {
    constructor(text,id=null){
        this.ruleText=text; this.listId=id; this.isException=!1; this.isScriptlet=!1; this.isCosmetic=!1; this.isRegex=!1; this.isCSP=!1; this.isRedirect=!1; this.isRemoveParam=!1; this.isCookie=!1; this.isGeneric=!1; this.isPopup=!1; this.isAll=!1; this.isDenyAllow=!1; this.isMethod=!1; this.isHeader=!1; this.isUriTransform=!1; this.isReplace=!1; this.isPermissions=!1; this.isTo=!1; this.isFrom=!1; this.isBadFilter=!1; this.isImportant=!1; this.isGenericHide=!1; this.isSpecificHide=!1; this.isElemHide=!1;         this.isGenericBlock=!1; this.isProcedural=!1; this.isMedia=!1; this.isHtmlFilter=!1;
        this.modifiers={domain:null,thirdParty:null,firstParty:null,script:null,image:null,stylesheet:null,object:null,xmlhttprequest:null,media:null,font:null,websocket:null,document:null,popup:null,csp:null,redirect:null,removeparam:null,cookie:null,if:null,all:null,denyallow:null,method:null,header:null,uritransform:null,replace:null,permissions:null,to:null,from:null};
        this.domain=null; this.cosmeticDomains=[]; this.path=null; this.regex=null; this.regexFlags=null; this.cosmeticSelector=null; this.scriptletCode=null; this.cspDirective=null; this.redirectResource=null; this.paramsToRemove=[]; this.cookieRule=null; this.condition=null; this.denyAllowDomains=[]; this.methods=[]; this.headers=[]; this.uriTransform=null; this.replacePattern=null; this.permissions=null; this.toDomains=[]; this.fromDomains=[]; this._compiledPathRegex=null; this._compiledReplace=null;
        this.parse(text)
    }
    parse(t){
        let text=t.trim(); if(!text)return;
        if(text.startsWith('@@')){this.isException=!0; text=text.slice(2)}
        if(text.includes('#@#+js')||text.includes('##+js')){this.isScriptlet=!0; const ex=text.includes('#@#+js'); if(ex)this.isException=!0; const p=text.split(ex?'#@#+js':'##+js'); if(p.length===2){if(p[0]){this.domain=p[0]; this.cosmeticDomains=parseCosmeticDomains(p[0])} this.scriptletCode=p[1]} return}
        if(text.includes('#@$#')||text.includes('#$#')){this.isScriptlet=!0; const ex=text.includes('#@$#'); if(ex)this.isException=!0; const p=text.split(ex?'#@$#':'#$#'); if(p.length===2){if(p[0]){this.domain=p[0]; this.cosmeticDomains=parseCosmeticDomains(p[0])} this.scriptletCode=parseAdGuardScriptletCode(p[1])} return}
        if(text.includes('#@?#')){this.isCosmetic=!0; this.isException=!0; const p=text.split('#@?#'); if(p.length===2){if(p[0]){this.domain=p[0]; this.cosmeticDomains=parseCosmeticDomains(p[0])} this.cosmeticSelector=p[1]; this.isProcedural=!0; this.validate(this.cosmeticSelector)} return}
        if(text.includes('#?#')){this.isCosmetic=!0; const p=text.split('#?#'); if(p.length===2){if(p[0]){this.domain=p[0]; this.cosmeticDomains=parseCosmeticDomains(p[0])} this.cosmeticSelector=p[1]; this.isProcedural=!0; this.validate(this.cosmeticSelector)} return}
        if(text.includes('#@#')){this.isCosmetic=!0; this.isException=!0; const p=text.split('#@#'); if(p.length===2){if(p[0]){this.domain=p[0]; this.cosmeticDomains=parseCosmeticDomains(p[0])} this.cosmeticSelector=p[1]; this.validate(this.cosmeticSelector)} return}
        if(text.includes('##')){this.isCosmetic=!0; const p=text.split('##'); if(p.length===2){if(p[0]){this.domain=p[0]; this.cosmeticDomains=parseCosmeticDomains(p[0])} let sel=p[1]; if(sel.startsWith('^')){this.isHtmlFilter=!0; sel=sel.slice(1)} this.cosmeticSelector=sel; this.validate(this.cosmeticSelector)} return}
        const matchOpt=(re,fn)=>{const m=text.match(re); if(m){fn(m[1]); text=text.replace(re,'')}}
        // `$` varsa seçenek bölümü mevcuttur; virgül-formu (`$script,domain=`)
        // ancak bu durumda seçenek sayılır (desendeki virgüller korunur).
        const hadOptions=text.includes('$');
        matchOpt(/\$denyallow=([^,]+)/,v=>{this.isDenyAllow=!0; this.denyAllowDomains=v.split('|')});
        matchOpt(/\$method=([^,]+)/,v=>{this.isMethod=!0; this.methods=v.split('|')});
        matchOpt(/\$header=([^,]+)/,v=>{this.isHeader=!0; this.headers=v.split('|')});
        matchOpt(/\$uritransform=([^,]+)/,v=>{this.isUriTransform=!0; this.uriTransform=v});
        matchOpt(/\$replace=([^,]+)/,v=>{this.isReplace=!0; this.replacePattern=v});
        matchOpt(/\$permissions=([^,]+)/,v=>{this.isPermissions=!0; this.permissions=v});
        matchOpt(/\$to=([^,]+)/,v=>{this.isTo=!0; this.toDomains=v.split('|')});
        matchOpt(/\$from=([^,]+)/,v=>{this.isFrom=!0; this.fromDomains=v.split('|')});
        matchOpt(/\$csp=([^,]+)/,v=>{this.isCSP=!0; this.cspDirective=v});
        matchOpt(/\$redirect=([^,]+)/,v=>{this.isRedirect=!0; this.redirectResource=v});
        matchOpt(/\$removeparam=([^,]+)/,v=>{this.isRemoveParam=!0; this.paramsToRemove=v.split('|')});
        if(/\$removeparam\b/.test(text)){this.isRemoveParam=!0; this.removeAllParams=!0; text=text.replace(/\$removeparam\b/,'')}
        matchOpt(/\$cookie=([^,]+)/,v=>{this.isCookie=!0; this.cookieRule=v});
        if(text.includes('$popup')){this.isPopup=!0; text=text.replace(/\$popup/,'')}
        if(text.includes('$all')){this.isAll=!0; text=text.replace(/\$all/,'')}
        if(text.includes('$badfilter')){this.isBadFilter=!0; text=text.replace(/\$badfilter/,'')}
        if(text.includes('$important')){this.isImportant=!0; text=text.replace(/\$important/,'')}
        if(text.includes('$1p')&&!text.includes('$1p=')){this.modifiers.firstParty=!0; text=text.replace(/\$1p\b/,'')}
        if(text.includes('$~1p')){this.modifiers.firstParty=!1; text=text.replace(/\$~1p\b/,'')}
        if(text.includes('$3p')&&!text.includes('$3p=')){this.modifiers.thirdParty=!0; text=text.replace(/\$3p\b/,'')}
        if(text.includes('$~3p')){this.modifiers.thirdParty=!1; text=text.replace(/\$~3p\b/,'')}
        if(/\$~doc\b/.test(text)){this.modifiers.document=!1; text=text.replace(/\$~doc\b/,'')}
        if(/\$doc\b/.test(text)){this.modifiers.document=!0; text=text.replace(/\$doc\b/,'')}
        if(/\$subdocument\b/.test(text)){this.modifiers.sub_frame=!0; text=text.replace(/\$subdocument\b/,'')}
        if(/\$~subdocument\b/.test(text)){this.modifiers.sub_frame=!1; text=text.replace(/\$~subdocument\b/,'')}
        if(/\$generichide\b|\$ghide\b/.test(text)){this.isGenericHide=!0; text=text.replace(/\$generichide\b|\$ghide\b/,'')}
        if(/\$genericblock\b/.test(text)){this.isGenericBlock=!0; text=text.replace(/\$genericblock\b/,'')}
        if(/\$specifichide\b|\$shide\b/.test(text)){this.isSpecificHide=!0; text=text.replace(/\$specifichide\b|\$shide\b/,'')}
        if(/\$elemhide\b|\$ehide\b/.test(text)){this.isElemHide=!0; text=text.replace(/\$elemhide\b|\$ehide\b/,'')}
        matchOpt(/\$domain=([^,]+)/,v=>{this.modifiers.domain=v.split('|')});
        // Virgül-formu normalizasyonu (standart ABP: `$script,image,third-party`
        // yazımında ilkten sonraki seçeneklerin başında `$` YOKTUR).
        // `=`-değerli seçenekler (`$domain=` vb.) üstte tüketildi; burada kalan
        // `,opt` parçaları tip/kapsam bayrağıdır ve `$opt` biçimine çevrilir.
        // Yalnızca seçenek kuyruğuna dokunulur, desen bölgesi korunur.
        // (Çevrilmezse `,image` gibi parçalar desene sızıp `||host,image`
        // gibi asla eşleşmeyen ölü DNR kuralları üretir.)
        (function(){
            const extra = ['third-party','first-party','1p','3p','all','popup','important','badfilter','doc','subdocument','generichide','ghide','genericblock','specifichide','shide','elemhide','ehide'];
            const names = TYPE_MODIFIERS.concat(extra).join('|');
            const normTail = (t) => t.replace(new RegExp(',(~?(?:' + names + '))(?=,|$)', 'g'), '$$$1');
            const di = text.indexOf('$');
            if(di !== -1){
                text = text.slice(0, di) + normTail(text.slice(di));
            }else{
                // `$` kalmadıysa (örn. `$domain=` tüketildiyse) sondaki
                // `,opt` dizisi seçenektir: `||x^,script` -> `||x^$script`.
                const m = text.match(new RegExp('((?:,(?:~?(?:' + names + ')))+)$'));
                if(m) text = text.slice(0, text.length - m[1].length) + normTail('$' + m[1].slice(1));
            }
        })();
        // `=`-değerli seçeneklerin virgül-formu (`$script,domain=a.com`):
        // `$`-formlar üstte tüketildi; kalan `,opt=değer` parçaları buradan alınır.
        if(hadOptions){
            matchOpt(/,denyallow=([^,]+)/,v=>{this.isDenyAllow=!0; this.denyAllowDomains=v.split('|')});
            matchOpt(/,method=([^,]+)/,v=>{this.isMethod=!0; this.methods=v.split('|')});
            matchOpt(/,header=([^,]+)/,v=>{this.isHeader=!0; this.headers=v.split('|')});
            matchOpt(/,uritransform=([^,]+)/,v=>{this.isUriTransform=!0; this.uriTransform=v});
            matchOpt(/,replace=([^,]+)/,v=>{this.isReplace=!0; this.replacePattern=v});
            matchOpt(/,permissions=([^,]+)/,v=>{this.isPermissions=!0; this.permissions=v});
            matchOpt(/,to=([^,]+)/,v=>{this.isTo=!0; this.toDomains=v.split('|')});
            matchOpt(/,from=([^,]+)/,v=>{this.isFrom=!0; this.fromDomains=v.split('|')});
            matchOpt(/,csp=([^,]+)/,v=>{this.isCSP=!0; this.cspDirective=v});
            matchOpt(/,redirect=([^,]+)/,v=>{this.isRedirect=!0; this.redirectResource=v});
            matchOpt(/,removeparam=([^,]+)/,v=>{this.isRemoveParam=!0; this.paramsToRemove=v.split('|')});
            matchOpt(/,cookie=([^,]+)/,v=>{this.isCookie=!0; this.cookieRule=v});
            matchOpt(/,domain=([^,]+)/,v=>{this.modifiers.domain=(this.modifiers.domain||[]).concat(v.split('|'))});
            if(/,removeparam\b(?![=])/.test(text)){this.isRemoveParam=!0; this.removeAllParams=!0; text=text.replace(/,removeparam\b(?![=])/,'')}
        }
        // Normalize ile üretilen `$`-formları için ikinci geçiş (üstteki
        // `$popup`/`$1p`/`$doc`/hide blokları normalizasyondan önce çalıştı).
        if(text.includes('$popup')){this.isPopup=!0; text=text.replace(/\$popup/,'')}
        if(text.includes('$all')){this.isAll=!0; text=text.replace(/\$all/,'')}
        if(text.includes('$badfilter')){this.isBadFilter=!0; text=text.replace(/\$badfilter/,'')}
        if(text.includes('$important')){this.isImportant=!0; text=text.replace(/\$important/,'')}
        if(text.includes('$1p')&&!text.includes('$1p=')){this.modifiers.firstParty=!0; text=text.replace(/\$1p\b/,'')}
        if(text.includes('$~1p')){this.modifiers.firstParty=!1; text=text.replace(/\$~1p\b/,'')}
        if(text.includes('$3p')&&!text.includes('$3p=')){this.modifiers.thirdParty=!0; text=text.replace(/\$3p\b/,'')}
        if(text.includes('$~3p')){this.modifiers.thirdParty=!1; text=text.replace(/\$~3p\b/,'')}
        if(/\$~doc\b/.test(text)){this.modifiers.document=!1; text=text.replace(/\$~doc\b/,'')}
        if(/\$doc\b/.test(text)){this.modifiers.document=!0; text=text.replace(/\$doc\b/,'')}
        if(/\$subdocument\b/.test(text)){this.modifiers.sub_frame=!0; text=text.replace(/\$subdocument\b/,'')}
        if(/\$~subdocument\b/.test(text)){this.modifiers.sub_frame=!1; text=text.replace(/\$~subdocument\b/,'')}
        if(/\$generichide\b|\$ghide\b/.test(text)){this.isGenericHide=!0; text=text.replace(/\$generichide\b|\$ghide\b/,'')}
        if(/\$genericblock\b/.test(text)){this.isGenericBlock=!0; text=text.replace(/\$genericblock\b/,'')}
        if(/\$specifichide\b|\$shide\b/.test(text)){this.isSpecificHide=!0; text=text.replace(/\$specifichide\b|\$shide\b/,'')}
        if(/\$elemhide\b|\$ehide\b/.test(text)){this.isElemHide=!0; text=text.replace(/\$elemhide\b|\$ehide\b/,'')}
        // Virgül-formu seçenekler: `$script,third-party` yazımında ikinci ve
        // sonraki seçeneklerin başında `$` YOKTUR (standart ABP sözdizimi).
        // `~` önekleri olumsuzdur. (MV3 düzeltmesi: önceden desenin içine sızıyordu.)
        if(/[,$]~third-party/.test(text)){this.modifiers.thirdParty=!1; text=text.replace(/[,$]~third-party/g,'')}
        if(/[,$]~first-party/.test(text)){this.modifiers.firstParty=!1; text=text.replace(/[,$]~first-party/g,'')}
        if(/[,$]third-party/.test(text)){this.modifiers.thirdParty=!0; text=text.replace(/[,$]third-party/g,'')}
        if(/[,$]first-party/.test(text)){this.modifiers.firstParty=!0; text=text.replace(/[,$]first-party/g,'')}
        if(text.includes('$third-party')){this.modifiers.thirdParty=!0; text=text.replace(/\$third-party/,'')}
        if(text.includes('$~third-party')){this.modifiers.thirdParty=!1; text=text.replace(/\$~third-party/,'')}
        if(text.includes('$first-party')){this.modifiers.firstParty=!0; text=text.replace(/\$first-party/,'')}
        if(text.includes('$~first-party')){this.modifiers.firstParty=!1; text=text.replace(/\$~first-party/,'')}
        for(const t of TYPE_MODIFIERS){if(new RegExp('\\$'+t).test(text)){this.modifiers[t]=!0; text=text.replace(new RegExp('\\$'+t),'')} if(new RegExp('\\$~'+t).test(text)){this.modifiers[t]=!1; text=text.replace(new RegExp('\\$~'+t),'')}}
        if(text.includes('$media')){this.modifiers.media=true; this.isMedia=true; text=text.replace(/\$media/g,'')}
        if(text.includes('$~media')){this.modifiers.media=false; text=text.replace(/\$~media/g,'')}
        if(text.includes('$object')){this.modifiers.object=true; text=text.replace(/\$object/g,'')}
        if(text.includes('$~object')){this.modifiers.object=false; text=text.replace(/\$~object/g,'')}
        if(text.includes('$other')){this.modifiers.other=true; text=text.replace(/\$other/g,'')}
        if(text.includes('$~other')){this.modifiers.other=false; text=text.replace(/\$~other/g,'')}
        matchOpt(/\$if=([^,]+)/,v=>{this.condition=v});
        text=text.replace(/\$+$/,'').trim(); if(text.endsWith('$'))text=text.slice(0,-1);
        const regexMatch=text.match(/^\/(.+)\/([a-z]*)$/i);
        if(text.startsWith('/')&&regexMatch){this.isRegex=!0; try{this.regex=new RegExp(regexMatch[1],regexMatch[2]||'i'); this.regexFlags=regexMatch[2]||'i'}catch(e){try{this.regex=new RegExp(regexMatch[1],'i'); this.regexFlags='i'}catch(e2){this.isRegex=!1}} return}
        if(text.startsWith('||')){const rest=text.slice(2), de=rest.indexOf('/'); if(de>0){this.domain=rest.slice(0,de); this.path=rest.slice(de)}else{const pi=rest.indexOf('^'); if(pi>0){this.domain=rest.slice(0,pi); this.path=rest.slice(pi)}else{this.domain=rest; this.path=''}} if(this.domain?.startsWith('*.'))this.domain=this.domain.slice(2); if(this.path)this.path=this.path.replace(/\^/g,'')}
        else if(text.includes('://')){try{const u=new URL(text); this.domain=u.hostname; this.path=u.pathname+u.search}catch(e){}}
        else if(text.includes('/')){const p=text.split('/'); if(p.length>=2){this.domain=p[0]||null; this.path='/'+p.slice(1).join('/'); if(this.domain?.startsWith('*.'))this.domain=this.domain.slice(2)}}
        else{this.domain=text; this.path=''}
        // Çıplak Pattern Desteği (_reklama_ gibi)
        if(!this.isRegex && !this.domain && !this.path){
            if(/^[a-zA-Z0-9_\-\.]+$/.test(text) && !text.includes('://') && !text.includes('*')){
                this.path = text; this.isGeneric = true; return;
            }
            if(text.includes('*') && !text.includes('://') && !text.includes('/')){
                this.path = text; this.isGeneric = true;
                try{this._compiledPathRegex = new RegExp(text.replace(/\*/g,'.*'))}catch{}
                return;
            }
        }
    }
    validate(s){if(!s)return; for(const p of DANGEROUS_SELECTOR_PATTERNS)if(p.test(s)){this.cosmeticSelector=null; this.isCosmetic=!1; return} if(PROCEDURAL_SELECTOR_PATTERN.test(s)){this.isProcedural=!0; return} if(typeof document==='undefined')return; try{document.querySelector(s)}catch(e){this.cosmeticSelector=null; this.isCosmetic=!1}}
    matches(uo,pu=null,ph=null,rt=null,rm=null,rh=null){
        try{
            if(this.isGeneric && this.path){
                const urlStr = uo.href;
                if(this.path.includes('*')){
                    if(this._compiledPathRegex){if(!this._compiledPathRegex.test(urlStr))return false}
                    else{try{const regex=new RegExp(this.path.replace(/\*/g,'.*')); if(!regex.test(urlStr))return false}catch{return false}}
                } else {if(!urlStr.includes(this.path))return false}
            }
            const host=uo.hostname.toLowerCase(), path=uo.pathname+uo.search;
            if(this.isCosmetic||this.isScriptlet)return this.matchesCosmetic(uo.href,pu);
            if(!this.isRegex&&!this.domain&&!this.path)return!1;
            if(this.domain&&!domainMatches(this.domain,host))return!1;
            if(this.path&&!this.matchPath(path))return!1;
            if(this.isRegex&&this.regex&&!this.regex.test(uo.href))return!1;
            if(this.isDenyAllow&&this.denyAllowDomains.length){let ok=!1; for(const d of this.denyAllowDomains)if(domainMatches(d,host)){ok=!0; break} if(ok)return!1}
            if(this.isMethod&&this.methods.length&&rm&&!this.methods.includes(rm.toUpperCase()))return!1;
            if(this.isHeader&&this.headers.length&&rh){let hm=!1; for(const h of this.headers){const[n,v]=h.split(':'); const N=n.trim(), V=v.trim(); for(const hdr of rh)if(hdr.name.toLowerCase()===N.toLowerCase()&&(!V||hdr.value.includes(V))){hm=!0; break} if(hm)break} if(!hm)return!1}
            if(this.isTo&&this.toDomains.length){let tm=!1; for(const d of this.toDomains)if(domainMatches(d,host)){tm=!0; break} if(!tm)return!1}
            if(this.isFrom&&this.fromDomains.length){let phl=ph; if(!phl&&pu)try{phl=new URL(pu).hostname}catch(e){return!1} if(!phl)return!1; let fm=!1; for(const d of this.fromDomains)if(domainMatches(d,phl)){fm=!0; break} if(!fm)return!1}
            if(this.modifiers.domain){let phl=ph; if(!phl&&pu)try{phl=new URL(pu).hostname}catch(e){return!1} if(!phl)return!1; const pos=[], neg=[]; for(const d of this.modifiers.domain){if(d.startsWith('~'))neg.push(d.slice(1)); else pos.push(d)} for(const nd of neg)if(domainMatches(nd,phl))return!1; if(pos.length&&!pos.some(pd=>domainMatches(pd,phl)))return!1}
            if(this.modifiers.thirdParty!==null){let phl=ph; if(!phl&&pu)try{phl=new URL(pu).hostname}catch(e){return!1} if(!phl)return!1; const is3p=!isSameSite(host,phl); if(this.modifiers.thirdParty!==is3p)return!1}
            if(this.modifiers.firstParty!==null){let phl=ph; if(!phl&&pu)try{phl=new URL(pu).hostname}catch(e){return!1} if(!phl)return!1; const is3p=!isSameSite(host,phl); if(this.modifiers.firstParty!==!is3p)return!1}
            if(rt){const pos=[], neg=[]; for(const t of TYPE_MODIFIERS){if(this.modifiers[t]===!0)pos.push(t); else if(this.modifiers[t]===!1)neg.push(t)} if(pos.length){if(!pos.some(t=>requestTypeMatchesModifier(rt,t)))return!1}else if(neg.some(t=>requestTypeMatchesModifier(rt,t)))return!1}
            if(this.isAll)return!0;
            if(this.condition){if(this.condition.includes('document')&&!pu)return!1; if(this.condition.includes('third-party')){let phl=ph; if(!phl&&pu)try{phl=new URL(pu).hostname}catch(e){return!1} if(!phl||isSameSite(host,phl))return!1}}
            return!0
        }catch(e){return!1}
    }
    matchPath(p){if(!this.path)return!0; const pl=this.path.toLowerCase(); if(pl.includes('*')){if(this._compiledPathRegex===null)this._compilePathRegex(); if(this._compiledPathRegex)return this._compiledPathRegex.test(p); return p.includes(pl.replace(/\*/g,''))} return p.includes(pl)}
    _compilePathRegex(){try{const e=this.path.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g,'\\$&').replace(/\\\*/g,'.*'); this._compiledPathRegex=new RegExp('^'+e)}catch(e){this._compiledPathRegex=!1}}
    matchesCosmetic(u,pu){if(!pu)return!1; try{const ph=new URL(pu).hostname.toLowerCase(); if(this.cosmeticDomains?.length){const pos=this.cosmeticDomains.filter(d=>!d.negated), neg=this.cosmeticDomains.filter(d=>d.negated); for(const n of neg)if(domainMatches(n.domain,ph))return!1; if(pos.length)return pos.some(p=>domainMatches(p.domain,ph)); return!0} if(this.domain)return domainMatches(this.domain,ph); return!0}catch(e){return!1}}
}

// ============== PARSE FONKSİYONLARI ==============
// SW'nin uzun senkron bloklara takılmaması için verim (yield) aralığı.
const PARSE_YIELD_EVERY = 2000;
function yieldToEventLoop(){return new Promise(r=>setTimeout(r,0))}
async function parseFilterListToArray(text, id, preSanitized=false){
    const rules = [];
    // preSanitized=true: girdi indirme anında temizlenmiştir (sanitizeListText:
    // hosts->adblock + TLD + anlamsız + duplicate). Çift normalize ve kural
    // seviyesi TLD elekleri YOKTUR. preSanitized=false yalnızca güvenlik ağıdır.
    let src = text;
    if(!preSanitized){
        try{
            if(typeof globalThis.AdSecHosts !== 'undefined' && globalThis.AdSecHosts.normalizeListText){
                src = globalThis.AdSecHosts.normalizeListText(text);
            }
        }catch(e){ src = text; }
    }
    let n = 0;
    for(const line of src.split('\n')){
        if((n++ % PARSE_YIELD_EVERY) === 0 && n > 1) await yieldToEventLoop();
        const l = line.trim();
        if(!l)continue;
        // Eski sahte-site formatı `{orijinal;sahte,...}` / `[orijinal;sahte,...]`
        // tamamen kaldırıldı: bu satırlar yoksayılır (FilterRule'a verilmez).
        if((l.startsWith('{')&&l.endsWith('}'))||(l.startsWith('[')&&l.endsWith(']')))continue;
        if(l.startsWith('!')||l.startsWith('['))continue;
        // Jenerik kozmetik/scriptlet kuralları (`##.reklam`, `#@#...`, `#$#...`,
        // `#?#...` vb.) `#` ile başlar; yorum sanılıp elenmemelidir. Yalnızca
        // `#` + boşluk/son gibi gerçek yorum satırları atlanır.
        if(l.startsWith('#') && !/^(##|#@#|#\?#|#@\?#|#\$#|#@\$#)/.test(l))continue;
        // Hosts IP'siyle başlayan satır (yalnızca preSanitized=false yolunda
        // görülür; temiz listede bu forma rastlanmaz).
        if(/^(?:0\.0\.0\.0|127\.0\.0\.1|::1|::)\s+/i.test(l)){
            let conv = null;
            try{
                if(typeof globalThis.AdSecHosts !== 'undefined' && globalThis.AdSecHosts.hostsLineToAdblock){
                    conv = globalThis.AdSecHosts.hostsLineToAdblock(l);
                }
            }catch(e){ conv = null; }
            const arr = Array.isArray(conv) ? conv : (conv ? [conv] : []);
            for(const c of arr){
                try{
                    const rule = new FilterRule(c, id);
                    rules.push(rule);
                }catch(e){}
            }
            continue;
        }
        let rule;
        try{rule=new FilterRule(l, id)}catch(e){continue}
        rules.push(rule);
    }
    return rules;
}
function finalizeBadFilters(){if(!badFilterTexts.size)return; const strip=t=>t.replace(/^@@/,'').trim(); const arrs=[filterRules,cosmeticRules,scriptletRules,webRequestHandler.rules.csp,webRequestHandler.rules.redirect,webRequestHandler.rules.removeParam,webRequestHandler.rules.cookie,popupRules,webRequestHandler.rules.replace,webRequestHandler.rules.uriTransform]; for(const arr of arrs)for(let i=arr.length-1;i>=0;i--)if(badFilterTexts.has(strip(arr[i].ruleText)))arr.splice(i,1)}
// ============== BROADCAST ==============
function ruleDomainsForContent(r){
    if(r.cosmeticDomains&&r.cosmeticDomains.length)return r.cosmeticDomains;
    if(r.modifiers&&r.modifiers.domain)return r.modifiers.domain.map(d=>d.startsWith('~')?{domain:d.slice(1),negated:!0}:{domain:d,negated:!1});
    return[];
}
function buildContentRulesPayload(){
    return{
        cosmetic:cosmeticRules.map(r=>({domain:r.domain,domains:ruleDomainsForContent(r),selector:r.cosmeticSelector,isException:r.isException,isGenericHide:r.isGenericHide,isSpecificHide:r.isSpecificHide,isElemHide:r.isElemHide,isProcedural:r.isProcedural,isHtmlFilter:!!r.isHtmlFilter})),
        scriptlet:scriptletRules.map(r=>({domain:r.domain,domains:ruleDomainsForContent(r),code:r.scriptletCode,name:r.scriptletName||null,args:r.scriptletArgs||[],isException:r.isException})),
        hide:filterRules.filter(r=>r.isGenericHide||r.isSpecificHide||r.isElemHide).map(r=>({domain:r.domain,domains:ruleDomainsForContent(r),isException:r.isException,isGenericHide:r.isGenericHide,isSpecificHide:r.isSpecificHide,isElemHide:r.isElemHide}))
    };
}
async function broadcastRules(){const rules=buildContentRulesPayload(); try{if(!browser.tabs||!browser.tabs.query)return; const tabs=await browser.tabs.query({}); const targets=(tabs||[]).filter(t=>t.id!==undefined&&t.id>=0); await Promise.allSettled(targets.map(t=>browser.tabs.sendMessage(t.id,{namespace:'adsecurity',action:'updateRules',rules}).catch(()=>{})))}catch(e){}}

// ============== NAVİGASYON ==============
// MV3 uyumlu: webNavigation + tabs API'leri service worker'da kullanılabilir.
// Popup kapatma burada kalır (DNR ile yapılamaz).
try{
if(browser.webNavigation && browser.webNavigation.onCreatedNavigationTarget)
browser.webNavigation.onCreatedNavigationTarget.addListener(d=>{try{if(d.url){const h=new URL(d.url).hostname; if(hostnameUsesBlockedTLD(h)){browser.tabs.remove(d.tabId); return}}}catch(e){} if(!popupRules.length)return; let p=tabHostnames[d.sourceTabId]||''; if(!p||isSiteDisabled(p))return; if(d.url){const uo=webRequestHandler.parseUrl(d.url); if(!uo)return; for(const r of popupRules)if(r.matches(uo,d.sourceUrl)){browser.tabs.remove(d.tabId); return}}});

if(browser.webNavigation && browser.webNavigation.onBeforeNavigate)
browser.webNavigation.onBeforeNavigate.addListener(async d=>{
    if(d.frameId!==0)return;
    let h='';
    try{h=new URL(d.url).hostname}catch(e){return}
    // .click / .zip site ziyareti tamamen engellenir (disabled site bile olsa)
    if(hostnameUsesBlockedTLD(h)){try{await browser.tabs.update(d.tabId,{url:'about:blank'})}catch(e){} return}
});
}catch(e){}