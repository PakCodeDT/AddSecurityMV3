'use strict';
// MV3 içerik betiği (ISOLATED dünya).
if (typeof browser === 'undefined') {
    var browser = (typeof globalThis !== 'undefined' && (globalThis.browser || globalThis.chrome)) || {};
}

(function() {
    'use strict';

    // ============================================================
    // 1. KONFIGÜRASYON
    // ============================================================

    const IS_MOBILE = /Android|Mobile/i.test(navigator.userAgent) ||
        (typeof window.matchMedia === 'function' &&
         window.matchMedia('(max-width: 900px) and (pointer: coarse)').matches);

    const CONFIG = {
        debug: false,
        mutationObserver: true,
        scriptInjection: true,
        styleInjection: true,
        elementRemoval: true,
        attributeMonitoring: !IS_MOBILE,
        shadowDomSupport: !IS_MOBILE,
        iframeSupport: true,
        maxDomTraversal: IS_MOBILE ? 1500 : 5000,
        batchProcessing: true,
        debounceDelay: IS_MOBILE ? 350 : 100,
        cacheSize: 500,
        cacheTTL: 60000
    };

    // ============================================================
    // 2. GLOBAL DEĞİŞKENLER
    // ============================================================

    let cosmeticRules = [];
    let scriptletRules = [];
    let hideRules = [];
    let appliedSelectors = new Map();
    let appliedScriptlets = new Set();
    let observer = null;
    let pageHost = '';
    let pageUrl = '';
    let isProcessing = false;
    let siteDisabled = false;
    let elementCache = new WeakMap();
    let selectorCache = new Map();
    let cacheTimestamps = new Map();
    let cosmeticExceptions = new Set();

    // Sayfaya UYGULANABİLİR alt kümeler (pageHost sabittir; payload başına
    // bir kez hesaplanır). Mutation batch'leri domain eşleşmesi YAPMAZ —
    // her batch'te binlerce kuralı tekrar taramak yerine bu listeler işletilir.
    let activeCosmetic = [];
    let activeCosExceptions = new Set();
    let activeScriptlets = [];
    let activeScriptExceptions = new Set();
    let activeHideState = { genericHide: false, specificHide: false, elemHide: false };

    function recomputeActiveSets() {
        activeCosExceptions = new Set();
        for (const rule of cosmeticRules) {
            if (!rule.isException) continue;
            if (!ruleApplies(rule)) continue;
            activeCosExceptions.add(rule.selector);
        }
        activeScriptExceptions = new Set();
        for (const rule of scriptletRules) {
            if (!rule.isException) continue;
            if (!ruleApplies(rule)) continue;
            const { name, args } = getScriptletNameArgs(rule);
            if (!name) continue;
            activeScriptExceptions.add(scriptletKey(name, args));
        }
        activeHideState = computeHideState();
        activeCosmetic = [];
        for (const rule of cosmeticRules) {
            if (rule.isException) continue;
            if (!ruleApplies(rule)) continue;
            if (!shouldApplyCosmetic(rule, activeHideState)) continue;
            activeCosmetic.push(rule);
        }
        activeScriptlets = [];
        for (const rule of scriptletRules) {
            if (rule.isException) continue;
            if (!ruleApplies(rule)) continue;
            activeScriptlets.push(rule);
        }
    }

    // ============================================================
    // 3. YARDIMCI FONKSİYONLAR
    // ============================================================

    function log(...args) {
        if (CONFIG.debug) console.log('[AdSecurity Content]', ...args);
    }

    function warn(...args) {
        console.warn('[AdSecurity Content]', ...args);
    }

    function error(...args) {
        console.error('[AdSecurity Content]', ...args);
    }

    function getPageInfo() {
        try {
            pageUrl = window.location.href;
            pageHost = new URL(pageUrl).hostname.toLowerCase();
            return { url: pageUrl, host: pageHost };
        } catch (e) {
            pageHost = '';
            pageUrl = '';
            return { url: '', host: '' };
        }
    }
    getPageInfo();

    // Jokerli domain deseni -> RegExp önbelleği (kural başına derleme yok).
    const domainRegexCache = new Map();
    function wildcardToRegExp(p) {
        let re = domainRegexCache.get(p);
        if (re !== undefined) return re;
        try {
            re = new RegExp('^' + p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$');
        } catch { re = null; }
        if (domainRegexCache.size > 1000) domainRegexCache.clear();
        domainRegexCache.set(p, re);
        return re;
    }

    function domainMatches(pattern, hostname) {
        if (!pattern || !hostname) return false;
        const p = pattern.toLowerCase();
        const h = hostname.toLowerCase();
        if (p.startsWith('*.')) {
            const base = p.slice(2);
            return h === base || h.endsWith('.' + base);
        }
        if (p.startsWith('/') && p.endsWith('/')) {
            try { return new RegExp(p.slice(1, -1)).test(h); } catch { return false; }
        }
        if (p.includes('*')) {
            const regex = wildcardToRegExp(p);
            return regex ? regex.test(h) : false;
        }
        return h === p || h.endsWith('.' + p);
    }

    function matchesDomainList(domainList, hostname) {
        if (!domainList || domainList.length === 0) return true;
        let matched = false;
        let hasPositive = false;
        for (const d of domainList) {
            const domain = d.domain || d;
            const negated = d.negated || false;
            if (negated) {
                if (domainMatches(domain, hostname)) return false;
            } else {
                hasPositive = true;
                if (domainMatches(domain, hostname)) matched = true;
            }
        }
        return !hasPositive || matched;
    }

    function ruleApplies(rule) {
        if (!rule.domain && (!rule.domains || rule.domains.length === 0)) return true;
        if (rule.domains && rule.domains.length > 0) {
            return matchesDomainList(rule.domains, pageHost);
        }
        if (rule.domain) {
            return domainMatches(rule.domain, pageHost);
        }
        return true;
    }

    function escapeRegex(s) {
        return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    const PROCEDURAL_NAMES = [
        'has-text', 'has', 'matches-css-before', 'matches-css-after', 'matches-css',
        'matches-attr', 'matches-prop', 'xpath', 'upward', 'if-not', 'if',
        'watch-attrs', 'min-text-length', 'matches-media',
        'min-outer-width', 'max-outer-width', 'min-outer-height', 'max-outer-height',
        'others', 'remove', 'style'
    ];
    const PROCEDURAL_RE = new RegExp(':(' + PROCEDURAL_NAMES.join('|') + ')\\(', 'i');

    function isProceduralSelector(selector) {
        return PROCEDURAL_RE.test(selector || '');
    }

    function splitProceduralChain(selector) {
        const src = selector || '';
        const first = PROCEDURAL_RE.exec(src);
        if (!first) return { base: src, chain: [] };
        const base = src.slice(0, first.index).trim();
        const chain = [];
        let pos = first.index;
        while (pos < src.length) {
            const sub = src.slice(pos);
            const m = PROCEDURAL_RE.exec(sub);
            if (!m || m.index !== 0) break;
            const name = m[1].toLowerCase();
            const arg = extractProceduralArg(sub, name);
            chain.push({ name, arg: arg === null ? '' : arg });
            const parenStart = sub.indexOf('(');
            pos += parenStart + 1 + (arg ? arg.length : 0) + 1;
        }
        return { base, chain };
    }

    /** Procedural argümanını dengeli parantez ile çıkarır (:has-text, :has vb.) */
    function extractProceduralArg(selector, name) {
        const marker = ':' + name + '(';
        const idx = selector.toLowerCase().indexOf(marker.toLowerCase());
        if (idx === -1) return null;
        let depth = 0;
        let start = idx + marker.length;
        for (let i = start; i < selector.length; i++) {
            const ch = selector[i];
            if (ch === '(') depth++;
            else if (ch === ')') {
                if (depth === 0) return selector.slice(start, i);
                depth--;
            }
        }
        return null;
    }

    function isGenericCosmeticRule(rule) {
        return !rule.domain && (!rule.domains || rule.domains.length === 0);
    }

    function computeHideState() {
        let genericHide = false;
        let specificHide = false;
        let elemHide = false;
        for (const rule of hideRules) {
            if (!ruleApplies(rule)) continue;
            if (rule.isException) {
                if (rule.isGenericHide) genericHide = false;
                if (rule.isSpecificHide) specificHide = false;
                if (rule.isElemHide) elemHide = false;
            } else {
                if (rule.isGenericHide) genericHide = true;
                if (rule.isSpecificHide) specificHide = true;
                if (rule.isElemHide) elemHide = true;
            }
        }
        return { genericHide, specificHide, elemHide };
    }

    function shouldApplyCosmetic(rule, hideState) {
        if (hideState.elemHide) return false;
        if (isGenericCosmeticRule(rule) && hideState.genericHide) return false;
        if (!isGenericCosmeticRule(rule) && hideState.specificHide) return false;
        return true;
    }

    function applyRulesFromPayload(rules) {
        if (!rules) return;
        cosmeticRules = rules.cosmetic || [];
        scriptletRules = rules.scriptlet || [];
        hideRules = rules.hide || [];
        appliedSelectors.clear();
        appliedScriptlets.clear();
        cacheClear();
        recomputeActiveSets();
        processRules();
    }

    // SW uykudaysa ilk çağrı boş dönebilir; kuralsız kalmamak için
    // kısa aralıklarla birkaç kez yeniden dene. SW ilk açılışta uzak
    // listeleri indirirken (MB'larca) birkaç saniye sürebilir; boş payload
    // gelirse "henüz hazır değil" sayılıp denemeye devam edilir.
    function fetchRulesFromBackground(attempt) {
        attempt = attempt || 1;
        browser.runtime.sendMessage({ namespace: 'adsecurity', action: 'getContentRules' })
            .then((response) => {
                if (response && response.ok && response.rules) {
                    const r = response.rules;
                    const empty = (!r.cosmetic || !r.cosmetic.length) &&
                        (!r.scriptlet || !r.scriptlet.length) &&
                        (!r.hide || !r.hide.length);
                    applyRulesFromPayload(r);
                    // Kurallar gerçekten geldiyse dur; SW boot ediyorsa dene.
                    if (!empty || attempt >= 8) return;
                    setTimeout(() => fetchRulesFromBackground(attempt + 1), 750);
                } else if (attempt < 8) {
                    setTimeout(() => fetchRulesFromBackground(attempt + 1), 750);
                }
            })
            .catch(() => {
                if (attempt < 8) setTimeout(() => fetchRulesFromBackground(attempt + 1), 750);
            });
    }

    // ============================================================
    // 4. CACHE YÖNETİMİ
    // ============================================================

    function cacheGet(key) {
        const cached = selectorCache.get(key);
        if (!cached) return null;
        const now = Date.now();
        if (now - cacheTimestamps.get(key) > CONFIG.cacheTTL) {
            selectorCache.delete(key);
            cacheTimestamps.delete(key);
            return null;
        }
        return cached;
    }

    function cacheSet(key, value) {
        if (selectorCache.size >= CONFIG.cacheSize) {
            const oldest = selectorCache.keys().next().value;
            selectorCache.delete(oldest);
            cacheTimestamps.delete(oldest);
        }
        selectorCache.set(key, value);
        cacheTimestamps.set(key, Date.now());
    }

    function cacheClear() {
        selectorCache.clear();
        cacheTimestamps.clear();
        appliedSelectors.clear();
        appliedScriptlets.clear();
        cosmeticExceptions.clear();
        bulkStyleRules.clear();
        if (bulkStyleElement) {
            bulkStyleElement.remove();
            bulkStyleElement = null;
        }
    }

    // ============================================================
    // 5. PROSEDÜREL SEÇİCİ MOTORU (ISOLATED)
    // ============================================================

    class ProceduralSelectorEngine { constructor() {this.cache = new Map();}
        parseSelector(selector) {
            const cached = cacheGet('procedural:' + selector);
            if (cached) return cached;
            const { base, chain } = splitProceduralChain(selector);
            if (!chain.length) return null;
            const handlers = chain.map(({ name, arg }) => this.buildHandler(name, arg, selector));
            if (handlers.some(h => !h)) return null;
            const handler = {
                base,
                chain: handlers,
                isChain: chain.length > 1 || !!base
            };
            cacheSet('procedural:' + selector, handler);
            return handler;
        }

        buildHandler(name, arg, fullSelector) {
            switch (name) {
                case 'has-text': return this.parseHasTextArg(arg);
                case 'has': return this.parseHasArg(arg);
                case 'matches-css-before': return this.parseMatchesCssArg(arg, 'before');
                case 'matches-css-after': return this.parseMatchesCssArg(arg, 'after');
                case 'matches-css': return this.parseMatchesCssArg(arg);
                case 'matches-attr': return this.parseMatchesAttrArg(arg);
                case 'matches-prop': return this.parseMatchesPropArg(arg);
                case 'xpath': return this.parseXPathArg(arg);
                case 'upward': return this.parseUpwardArg(arg);
                case 'if': return this.parseIfArg(arg);
                case 'if-not': return this.parseIfNotArg(arg);
                case 'watch-attrs': return this.parseWatchAttrsArg(arg, fullSelector);
                case 'min-text-length': return this.parseMinTextLengthArg(arg);
                case 'matches-media': return this.parseMatchesMediaArg(arg);
                case 'min-outer-width': return this.parseOuterBoundArg('width', arg, 'min');
                case 'max-outer-width': return this.parseOuterBoundArg('width', arg, 'max');
                case 'min-outer-height': return this.parseOuterBoundArg('height', arg, 'min');
                case 'max-outer-height': return this.parseOuterBoundArg('height', arg, 'max');
                case 'others': return { type: 'others' };
                case 'remove': return { type: 'remove' };
                case 'style': return this.parseStyleArg(arg);
                default: return null;
            }
        }

        parseHasTextArg(inner) {
            if (inner === null) return null;
            let pattern = inner.replace(/^["']|["']$/g, '');
            if (pattern.includes(',') && !pattern.startsWith('/')) {
                const terms = pattern.split(',').map(t => t.trim().toLowerCase());
                return function(element) {
                    if (!element || !element.textContent) return false;
                    const text = element.textContent.toLowerCase();
                    return terms.some(term => text.includes(term));
                };
            }
            if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
                const lastSlash = pattern.lastIndexOf('/');
                const flags = pattern.slice(lastSlash + 1);
                const regexPattern = pattern.slice(1, lastSlash);
                try {
                    const regex = new RegExp(regexPattern, flags);
                    return function(element) {
                        if (!element || !element.textContent) return false;
                        return regex.test(element.textContent);
                    };
                } catch (e) {
                    warn('Invalid regex in :has-text():', pattern);
                    return null;
                }
            }
            
            const searchText = pattern.toLowerCase();
            return function(element) {
                if (!element || !element.textContent) return false;
                return element.textContent.toLowerCase().includes(searchText);
            };
        }

        parseMatchesCssArg(argStr, pseudo = '') {
            if (argStr === null) return null;
            let depth = 0;
            const parts = [];
            let current = '';
            for (let i = 0; i < argStr.length; i++) {
                const char = argStr[i];
                if (char === '(') depth++;
                else if (char === ')') depth--;
                else if (char === ':' && depth === 0) {
                    parts.push(current.trim());
                    current = '';
                    continue;
                }
                current += char;
            }
            if (current.trim()) parts.push(current.trim());
            if (!parts.length) return null;
            const property = parts[0];
            const value = parts.length > 1 ? parts.slice(1).join(':').trim() : '';
            return function(element) {
                if (!element) return false;
                try {
                    const computed = window.getComputedStyle(element, pseudo || null);
                    const actual = computed.getPropertyValue(property);
                    if (!value) return actual !== '';
                    return actual === value || actual.includes(value);
                } catch { return false; }
            };
        }

        parseMatchesAttrArg(arg) {
            if (arg === null) return null;
            const parts = arg.split('=');
            const name = parts[0].trim();
            const value = parts.length > 1 ? parts.slice(1).join('=').replace(/^["']|["']$/g, '').trim() : '';
            return function(element) {
                if (!element) return false;
                if (!element.hasAttribute(name)) return false;
                if (value && !element.getAttribute(name).includes(value)) return false;
                return true;
            };
        }

        parseMatchesPropArg(arg) {
            if (arg === null) return null;
            const parts = arg.split('=');
            const name = parts[0].trim();
            const value = parts.length > 1 ? parts.slice(1).join('=').replace(/^["']|["']$/g, '').trim() : '';
            return function(element) {
                if (!element) return false;
                if (!(name in element)) return false;
                if (value && String(element[name]) !== value && !String(element[name]).includes(value)) return false;
                return true;
            };
        }

        parseXPathArg(xpath) {
            if (xpath === null) return null;
            return function(element) {
                if (!element) return false;
                try {
                    const result = document.evaluate(xpath, element.ownerDocument || document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
                    return result.singleNodeValue === element;
                } catch { return false; }
            };
        }

        parseUpwardArg(upwardSelector) {
            return function(element) {
                if (!element) return null;
                if (upwardSelector) {
                    const parent = element.closest(upwardSelector.trim());
                    return parent || null;
                }
                return element.parentElement || null;
            };
        }

        parseIfArg(condition) {
            if (condition === null) return null;
            return function(element) {
                if (!element) return false;
                try { return element.closest(condition.trim()) !== null; } catch { return false; }
            };
        }

        parseIfNotArg(condition) {
            if (condition === null) return null;
            return function(element) {
                if (!element) return false;
                try { return element.closest(condition.trim()) === null; } catch { return false; }
            };
        }

        parseWatchAttrsArg(arg, fullSelector) {
            if (arg === null) return null;
            const attrs = arg.split(',').map(a => a.trim());
            return function(element) {
                if (!element) return false;
                const observer = new MutationObserver(() => {
                    querySelectorAllDeep(fullSelector).forEach(el => {
                        el.style.setProperty('display', 'none', 'important');
                    });
                });
                observer.observe(element, { attributes: true, attributeFilter: attrs });
                return true;
            };
        }

        parseMinTextLengthArg(arg) {
            const minLength = parseInt(arg, 10);
            if (isNaN(minLength)) return null;
            return function(element) {
                if (!element) return false;
                return element.textContent.trim().length >= minLength;
            };
        }

        parseMatchesMediaArg(arg) {
            if (arg === null) return null;
            const mediaQuery = arg.replace(/^["']|["']$/g, '');
            return function() {
                try { return window.matchMedia(mediaQuery).matches; } catch { return false; }
            };
        }

        parseOuterBoundArg(dim, arg, mode) {
            const limit = parseFloat(arg);
            if (isNaN(limit)) return null;
            return function(element) {
                if (!element) return false;
                const rect = element.getBoundingClientRect();
                const value = dim === 'width' ? rect.width : rect.height;
                return mode === 'min' ? value >= limit : value <= limit;
            };
        }

        parseStyleArg(styleDecl) {
            if (styleDecl === null) return null;
            return function(element) {
                if (!element) return false;
                for (const style of styleDecl.split(';')) {
                    const idx = style.indexOf(':');
                    if (idx === -1) continue;
                    const prop = style.slice(0, idx).trim();
                    const val = style.slice(idx + 1).trim();
                    if (prop && val) element.style.setProperty(prop, val, 'important');
                }
                return true;
            };
        }

        parseHasArg(innerSelector) {
            if (innerSelector === null) return null;
            const trimmed = innerSelector.trim();
            return function(element) {
                if (!element) return false;
                try { return element.querySelector(trimmed) !== null; } catch { return false; }
            };
        }

        applyOthersFilter(elements) {
            const parentMap = new Map();
            for (const el of elements) {
                const parent = el.parentElement;
                if (!parent) continue;
                if (!parentMap.has(parent)) parentMap.set(parent, []);
                parentMap.get(parent).push(el);
            }
            const out = [];
            for (const group of parentMap.values()) {
                for (let i = 1; i < group.length; i++) out.push(group[i]);
            }
            return out;
        }

        applyChain(base, chain, root) {
            let elements = [];
            if (base) {
                try { elements = Array.from(root.querySelectorAll(base)); } catch { elements = []; }
            } else {
                try { elements = Array.from(root.querySelectorAll('*')); } catch { elements = []; }
            }

            for (const handler of chain) {
                if (handler && handler.type === 'others') {
                    elements = this.applyOthersFilter(elements);
                    continue;
                }
                if (handler && handler.type === 'remove') {
                    for (const el of elements) {
                        if (el && el.remove) el.remove();
                    }
                    return [];
                }
                if (typeof handler === 'function' && handler.length === 0) {
                    if (!handler()) return [];
                    continue;
                }
                const next = [];
                for (const el of elements) {
                    const result = handler(el);
                    if (result === false || result === null) continue;
                    if (result === true) next.push(el);
                    else if (result instanceof Element) next.push(result);
                }
                elements = next;
            }
            return elements;
        }

        evaluateSelector(selector, root = document) {
            // Not: sonuç DİZİSİ önbelleğe alınmaz. Ölü DOM referansları tutar
            // ve yeni eklenen düğümleri TTL dolana kadar kaçırır. Yalnızca
            // ayrıştırılmış handler önbelleklidir (parseSelector).
            if (!isProceduralSelector(selector)) {
                try {
                    return Array.from(root.querySelectorAll(selector));
                } catch {
                    return [];
                }
            }

            const parsed = this.parseSelector(selector);
            if (!parsed || !parsed.chain) {
                return [];
            }

            return this.applyChain(parsed.base, parsed.chain, root);
        }

        evaluateSelectorDeep(selector) {
            if (!isProceduralSelector(selector)) {
                return querySelectorAllDeep(selector);
            }
            const seen = new Set();
            forEachAccessibleDocument((doc) => {
                for (const el of this.evaluateSelector(selector, doc)) {
                    seen.add(el);
                }
            });
            return Array.from(seen);
        }
    }

    const proceduralEngine = new ProceduralSelectorEngine();

    // ============================================================
    // 6. KOZMETİK KURAL UYGULAMA
    // ============================================================

    function forEachAccessibleDocument(callback, rootDoc) {
        const root = rootDoc || document;
        callback(root);
        if (!CONFIG.iframeSupport) return;
        let frames;
        try { frames = root.querySelectorAll('iframe, frame'); } catch { return; }
        for (const frame of frames) {
            try {
                const doc = frame.contentDocument;
                if (doc) forEachAccessibleDocument(callback, doc);
            } catch {}
        }
    }

    function traverseShadowDOM(root, selector, callback) {
        if (!root) return;
        if (root.querySelectorAll) {
            let elements;
            try { elements = root.querySelectorAll(selector); } catch { elements = []; }
            for (const el of elements) callback(el);
        }
        if (CONFIG.shadowDomSupport) {
            const walker = document.createTreeWalker(
                root,
                NodeFilter.SHOW_ELEMENT,
                {
                    acceptNode: function(node) {
                        if (node.shadowRoot) return NodeFilter.FILTER_ACCEPT;
                        return NodeFilter.FILTER_SKIP;
                    }
                }
            );
            let node = walker.nextNode();
            while (node) {
                if (node.shadowRoot) {
                    traverseShadowDOM(node.shadowRoot, selector, callback);
                }
                node = walker.nextNode();
            }
        }
    }

    function querySelectorAllDeep(selector, rootDoc) {
        const seen = new Set();
        forEachAccessibleDocument((doc) => {
            traverseShadowDOM(doc, selector, (el) => seen.add(el));
            try {
                doc.querySelectorAll(selector).forEach((el) => seen.add(el));
            } catch {}
        }, rootDoc);
        return Array.from(seen);
    }

    let bulkStyleElement = null;
    const bulkStyleRules = new Set();

    function ensureBulkStyleSheet() {
        if (bulkStyleElement && bulkStyleElement.isConnected) return bulkStyleElement;
        bulkStyleElement = document.getElementById('adsecurity-bulk-cosmetic');
        if (!bulkStyleElement) {
            bulkStyleElement = document.createElement('style');
            bulkStyleElement.id = 'adsecurity-bulk-cosmetic';
            bulkStyleElement.setAttribute('data-adsecurity', 'true');
            (document.head || document.documentElement).appendChild(bulkStyleElement);
        }
        return bulkStyleElement;
    }

    function applyBulkCosmeticSelector(selector) {
        if (!selector || bulkStyleRules.has(selector)) return false;
        const styleEl = ensureBulkStyleSheet();
        const cssText = `${selector}{display:none!important;visibility:hidden!important;opacity:0!important;pointer-events:none!important;}`;
        try {
            // O(1) ekleme: tüm sheet'i baştan yazmak (O(N²)) yerine insertRule.
            styleEl.sheet.insertRule(cssText, styleEl.sheet.cssRules.length);
        } catch (e) {
            return false;
        }
        bulkStyleRules.add(selector);
        return true;
    }

    function removeBulkCosmeticSelector(selector) {
        if (!selector || !bulkStyleRules.delete(selector)) return;
        try {
            const sheet = bulkStyleElement && bulkStyleElement.sheet;
            if (!sheet) return;
            const rules = sheet.cssRules;
            for (let i = 0; i < rules.length; i++) {
                if (rules[i].selectorText === selector) { sheet.deleteRule(i); break; }
            }
        } catch (e) {}
    }

    function getProcessedElements(selector) {
        if (!appliedSelectors.has(selector)) {
            const ws = new WeakSet();
            appliedSelectors.set(selector, ws);
            return ws;
        }
        return appliedSelectors.get(selector);
    }

    function markElementsProcessed(selector, elements) {
        const ws = getProcessedElements(selector);
        for (const el of elements) {
            ws.add(el);
        }
    }

    function applyCosmeticRule(rule) {
        try {
            if (!rule.selector) return false;
            if (rule.isException) return false;

            const selector = rule.selector;
            const isProcedural = rule.isProcedural || isProceduralSelector(selector);

            // ##^ html-filtering: script gibi düğümleri gizlemek yetmez, DOM'dan çıkar.
            if (rule.isHtmlFilter) {
                const elements = isProcedural
                    ? proceduralEngine.evaluateSelectorDeep(selector)
                    : querySelectorAllDeep(selector);
                if (!elements.length) return false;
                for (const el of elements) {
                    if (el && el.remove) el.remove();
                }
                markElementsProcessed(selector, elements);
                return true;
            }

            if (/:remove\s*\(\s*\)/i.test(selector)) {
                const elements = isProcedural
                    ? proceduralEngine.evaluateSelectorDeep(selector)
                    : querySelectorAllDeep(selector);
                if (!elements.length) return false;
                for (const el of elements) {
                    if (el && el.remove) el.remove();
                }
                markElementsProcessed(selector, elements);
                return true;
            }

            if (/:style\s*\(/i.test(selector)) {
                const elements = isProcedural
                    ? proceduralEngine.evaluateSelectorDeep(selector)
                    : querySelectorAllDeep(selector);
                markElementsProcessed(selector, elements);
                return elements.length > 0;
            }

            if (!isProcedural) {
                return applyBulkCosmeticSelector(selector);
            }

            let elements = proceduralEngine.evaluateSelectorDeep(selector);
            if (elements.length === 0) return false;

            const processedWs = getProcessedElements(selector);
            const unprocessed = elements.filter(el => !processedWs.has(el));
            if (unprocessed.length === 0) return false;

            const styleId = 'adsecurity-cosmetic-' + selector.replace(/[^a-zA-Z0-9]/g, '-').slice(0, 120);
            let styleElement = document.getElementById(styleId);
            if (!styleElement) {
                styleElement = document.createElement('style');
                styleElement.id = styleId;
                styleElement.setAttribute('data-adsecurity', 'true');
                const className = 'adsecurity-hidden-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7);
                styleElement.setAttribute('data-adsecurity-class', className);
                styleElement.textContent = `.${className}{display:none!important;visibility:hidden!important;opacity:0!important;pointer-events:none!important;}`;
                (document.head || document.documentElement).appendChild(styleElement);
                for (const el of unprocessed) el.classList.add(className);
                markElementsProcessed(selector, unprocessed);
                log('Cosmetic rule applied:', selector, unprocessed.length, 'new elements');
                return true;
            }

            const className = styleElement.getAttribute('data-adsecurity-class');
            if (className) {
                for (const el of unprocessed) el.classList.add(className);
                markElementsProcessed(selector, unprocessed);
                return unprocessed.length > 0;
            }
            return false;
        } catch (e) {
            warn('Cosmetic rule error:', e);
            return false;
        }
    }

    // ============================================================
    // 7. MAIN WORLD İLE İLETİŞİM
    // ============================================================

    function setupMainWorldBridge() {
        window.addEventListener('message', function(event) {
            if (event.source !== window) return;
            if (event.data && event.data.type === 'adsecurity-main-to-isolated') {
                const payload = event.data.payload;
                if (payload.action === 'scriptletResult') {
                    log('Scriptlet result from MAIN:', payload);
                }
            }
        });
    }

    function forwardScriptletToMain(name, args) {
        try {
            window.postMessage({
                type: 'adsecurity-isolated-to-main',
                payload: {
                    action: 'executeScriptlet',
                    name: name,
                    args: args
                }
            }, '*');
        } catch (e) {}
    }

    // ============================================================
    // 8. SCRIPLET YÖNETİMİ (ISOLATED - Sadece yönlendirme)
    // ============================================================

    function scriptletKey(name, args) {
        return name + '|' + JSON.stringify(args || []);
    }

    // Background ile aynı ayrıştırma mantığı (tırnak/regex/kaçış-duyarlı):
    // yeni payload'da name/args gelir, eski payload'da sadece code olabilir.
    function isFbRegexStart(s, i) {
        let j = i - 1;
        while (j >= 0 && /\s/.test(s[j])) j--;
        if (j < 0) return true;
        return '([{=:,!&|?;'.includes(s[j]);
    }
    function fbHasClosingSlash(s, i) {
        let inClass = false;
        for (let k = i + 1; k < s.length; k++) {
            const c = s[k];
            if (c === '\\') { k++; continue; }
            if (c === '[') { inClass = true; continue; }
            if (c === ']' && inClass) { inClass = false; continue; }
            if (c === '/' && !inClass) return true;
        }
        return false;
    }
    function fbFindMatchingParen(s, openIdx) {
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
            if (ch === '/' && isFbRegexStart(s, i) && fbHasClosingSlash(s, i)) { inRe = true; continue; }
            if (ch === '(') depth++;
            else if (ch === ')') { depth--; if (depth === 0) return i; }
        }
        return -1;
    }
    function fbSplitArgs(str) {
        const args = [];
        let cur = '', q = null, inRe = false, pd = 0, bd = 0, cd = 0;
        const reStart = () => {
            const t = cur.replace(/\s+$/, '');
            if (t === '') return true;
            return '([{=:,!&|?;'.includes(t[t.length - 1]);
        };
        for (let i = 0; i < str.length; i++) {
            const ch = str[i];
            if (inRe) {
                cur += ch;
                if (ch === '\\') { i++; cur += str[i] || ''; continue; }
                if (ch === '/') {
                    while (i + 1 < str.length && /[gimsuy]/.test(str[i + 1])) { i++; cur += str[i]; }
                    inRe = false;
                }
                continue;
            }
            if (q) {
                if (ch === '\\') { cur += ch + (str[i + 1] || ''); i++; continue; }
                if (ch === q) q = null;
                cur += ch; continue;
            }
            if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
            if (ch === '\\') { cur += ch + (str[i + 1] || ''); i++; continue; }
            if (ch === '/' && reStart() && fbHasClosingSlash(str, i)) { inRe = true; cur += ch; continue; }
            if (ch === '(') { pd++; cur += ch; continue; }
            if (ch === ')') { if (pd > 0) { pd--; cur += ch; continue; } }
            if (ch === '[') { bd++; cur += ch; continue; }
            if (ch === ']') { if (bd > 0) { bd--; cur += ch; continue; } }
            if (ch === '{') { cd++; cur += ch; continue; }
            if (ch === '}') { if (cd > 0) { cd--; cur += ch; continue; } }
            if (ch === ',' && pd === 0 && bd === 0 && cd === 0) { args.push(cur.trim()); cur = ''; continue; }
            cur += ch;
        }
        if (cur.trim()) args.push(cur.trim());
        return args.map(a => (a.length >= 2 && ((a[0] === '"' && a[a.length - 1] === '"') || (a[0] === "'" && a[a.length - 1] === "'"))) ? a.slice(1, -1) : a);
    }
    function parseScriptletCodeFallback(rawCode) {
        if (!rawCode || typeof rawCode !== 'string') return { name: null, args: [] };
        let code = rawCode.trim().replace(/;$/, '');
        for (;;) {
            if (!(code.length > 1 && code[0] === '(')) break;
            if (fbFindMatchingParen(code, 0) === code.length - 1) { code = code.slice(1, -1).trim(); continue; }
            break;
        }
        const m = code.match(/^(trusted-[\w.-]+|[\w.-]+)/);
        if (!m) return { name: null, args: [] };
        const name = m[1];
        const rest = code.slice(name.length).trim();
        if (rest === '' || rest === '()') return { name, args: [] };
        let argsStr;
        const rt = rest.trim();
        if (rt[0] === '(') {
            const close = fbFindMatchingParen(rt, 0);
            argsStr = close !== -1 ? rt.slice(1, close) : rt;
        } else {
            argsStr = rest.replace(/^\s*,/, '');
        }
        if (argsStr.trim() === '') return { name, args: [] };
        return { name, args: fbSplitArgs(argsStr) };
    }

    function getScriptletNameArgs(rule) {
        if (rule.name) return { name: rule.name, args: rule.args || [] };
        if (rule.code) return parseScriptletCodeFallback(rule.code);
        return { name: null, args: [] };
    }

    function processScriptletRules(scriptletExceptions) {
        let count = 0;
        for (const rule of scriptletRules) {
            if (!ruleApplies(rule)) continue;
            if (rule.isException) continue;
            const { name, args } = getScriptletNameArgs(rule);
            if (!name) continue;
            const key = scriptletKey(name, args);
            if (scriptletExceptions.has(key)) continue;
            if (appliedScriptlets.has(key)) continue;
            forwardScriptletToMain(name, args);
            appliedScriptlets.add(key);
            count++;
        }
        return count;
    }

    // ============================================================
    // 9. MUTATION OBSERVER
    // ============================================================

    function setupObserver() {
        if (observer) {
            observer.disconnect();
        }

        observer = new MutationObserver(function(mutations) {
            if (siteDisabled || (cosmeticRules.length === 0 && scriptletRules.length === 0)) {
                return;
            }

            let needsProcessing = false;
            let processedCount = 0;

            for (const mutation of mutations) {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    needsProcessing = true;
                    processedCount += mutation.addedNodes.length;
                }
                if (mutation.type === 'attributes' && mutation.attributeName) {
                    needsProcessing = true;
                }
                if (processedCount > CONFIG.maxDomTraversal) {
                    break;
                }
            }

            if (needsProcessing) {
                clearTimeout(window._adsecurityObserverTimeout);
                window._adsecurityObserverTimeout = setTimeout(function() {
                    if (CONFIG.batchProcessing) {
                        processRulesBatched();
                    } else {
                        processRules();
                    }
                }, CONFIG.debounceDelay);
            }
        });

        const observeOpts = {
            childList: true,
            subtree: true
        };

        if (CONFIG.attributeMonitoring) {
            observeOpts.attributes = true;
            observeOpts.attributeFilter = ['style', 'class', 'id', 'display', 'hidden'];
        }

        // document_start anında documentElement henüz yok olabilir.
        const root = document.documentElement || document;
        try {
            observer.observe(root, observeOpts);
        } catch (e) { return; }
        log('Mutation observer setup complete', IS_MOBILE ? '(mobile-throttled)' : '');
    }

    // ============================================================
    // 10. KURAL İŞLEME
    // ============================================================

    function processRulesBatched() {
        if (isProcessing || siteDisabled) return;
        if (activeCosmetic.length === 0 && activeScriptlets.length === 0) return;

        isProcessing = true;
        try {
            let cosmeticCount = 0;

            for (const rule of activeCosmetic) {
                if (activeCosExceptions.has(rule.selector)) {
                    const styleId = 'adsecurity-cosmetic-' + rule.selector.replace(/[^a-zA-Z0-9]/g, '-').slice(0, 120);
                    const styleElement = document.getElementById(styleId);
                    if (styleElement) styleElement.remove();
                    removeBulkCosmeticSelector(rule.selector);
                    appliedSelectors.delete(rule.selector);
                    continue;
                }
                if (applyCosmeticRule(rule)) cosmeticCount++;
            }

            let scriptletCount = 0;
            if (activeScriptlets.length > 0) {
                scriptletCount = processScriptletRules(activeScriptExceptions);
            }

            log('Applied:', cosmeticCount, 'cosmetic rules,', scriptletCount, 'scriptlet rules');
        } catch (e) {
            error('Batch processing error:', e);
        } finally {
            isProcessing = false;
        }
    }

    function processRules() {
        if (document.readyState === 'loading') {
            setTimeout(processRules, 100);
            return;
        }
        log('Processing rules...');
        processRulesBatched();
    }

    // ============================================================
    // 11. MESAJ YÖNETİMİ
    // ============================================================

    function handleMessage(message, sender, sendResponse) {
        if (!message || message.namespace !== 'adsecurity') {
            sendResponse({ ok: false, error: 'Invalid namespace' });
            return true;
        }

        switch (message.action) {
            case 'updateRules':
                if (message.rules) {
                    applyRulesFromPayload(message.rules);
                    sendResponse({ ok: true });
                }
                break;

            case 'getRules':
                sendResponse({
                    ok: true,
                    cosmetic: cosmeticRules,
                    scriptlet: scriptletRules,
                    hide: hideRules
                });
                break;

            case 'ping':
                sendResponse({ ok: true });
                break;

            case 'clearCache':
                cacheClear();
                sendResponse({ ok: true });
                break;

            default:
                sendResponse({ ok: false, error: 'Unknown action: ' + message.action });
        }
        return true;
    }

    // ============================================================
    // 12. BAŞLANGIÇ
    // ============================================================

    function init() {
        log('Initializing AdSecurity content script (ISOLATED)...', IS_MOBILE ? '[mobile]' : '[desktop]');
        log('Page:', pageUrl);

        browser.runtime.onMessage.addListener(handleMessage);

        setupMainWorldBridge();
        fetchRulesFromBackground();

        browser.storage.local.get('adsecurity_disabled_sites').then((data) => {
            const list = Array.isArray(data.adsecurity_disabled_sites) ? data.adsecurity_disabled_sites : [];
            siteDisabled = !!(pageHost && list.includes(pageHost));

            if (!siteDisabled) {
                setupObserver();
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', processRules);
                } else {
                    setTimeout(processRules, 50);
                }
            }
        }).catch(() => {
            setupObserver();
            if (document.readyState === 'loading') {document.addEventListener('DOMContentLoaded', processRules);}
            else {setTimeout(processRules, 50);}
        });

        browser.storage.onChanged.addListener((changes, area) => {
            if (area !== 'local') return;

            if (changes.adsecurity_disabled_sites) {
                const list = Array.isArray(changes.adsecurity_disabled_sites.newValue)
                    ? changes.adsecurity_disabled_sites.newValue : [];
                const nowDisabled = !!(pageHost && list.includes(pageHost));
                if (nowDisabled === siteDisabled) return;
                siteDisabled = nowDisabled;
                if (siteDisabled) {
                    if (observer) { observer.disconnect(); observer = null; }
                    cacheClear();
                } else {
                    setupObserver();
                    processRules();
                }
            }
            if (changes.adsecurity_advanced_mode) {cacheClear();}
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('readystatechange', function() {
            if (document.readyState !== 'loading') {
                init();
            }
        });
    } else {
        init();
    }

})();