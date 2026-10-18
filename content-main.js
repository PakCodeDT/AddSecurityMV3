'use strict';
(function() {
    'use strict';
    // Paylaşımlı DOM gözlemcisi: her scriptlet kendi MutationObserver'ını
    // açmak yerine buraya abone olur (N observer x her mutasyon yerine 1x).
    // Yalnızca childList+subtree izlenir; attribute izleyenler ayrı kalır.
    const domWatchers = new Set();
    let domWatcherObserver = null;
    function watchDOM(cb) {
        domWatchers.add(cb);
        if (!domWatcherObserver) {
            domWatcherObserver = new MutationObserver((mutations) => {
                for (const fn of Array.from(domWatchers)) {
                    try { fn(mutations); } catch (e) {}
                }
            });
            try {
                const root = document.documentElement || document;
                domWatcherObserver.observe(root, { childList: true, subtree: true });
            } catch (e) {}
        }
        return () => { domWatchers.delete(cb); };
    }
    class MainScriptletEngine {
        constructor() {
            this.registeredScriptlets = new Map();
            this.injectedScriptlets = new Set();
            this.registerBuiltinScriptlets();
            this.registerTrustedScriptlets();
            this.registerAdvancedScriptlets();
        }
        register(name, fn) {this.registeredScriptlets.set(name, fn);}
        registerBuiltinScriptlets() {
            this.register('set-constant', function(prop, valueRaw) {
                if (!prop) return;
                const resolveValue = (raw) => {
                    if (raw === 'undefined') return undefined;
                    if (raw === 'null') return null;
                    if (raw === 'true') return true;
                    if (raw === 'false') return false;
                    if (raw === '') return '';
                    if (raw === 'emptyArr' || raw === '[]') return [];
                    if (raw === 'emptyObj' || raw === '{}') return {};
                    if (raw === 'noopFunc') return function(){};
                    if (raw === 'trueFunc') return function(){ return true; };
                    if (raw === 'falseFunc') return function(){ return false; };
                    if (raw === 'NaN') return NaN;
                    const n = Number(raw);
                    if (!isNaN(n) && raw.trim() !== '') return n;
                    return raw;
                };
                const value = resolveValue(valueRaw);
                const parts = prop.split('.');
                // Zincir tuzaklı: ara obje sonradan overwrite edilse bile yaprak değer korunur.
                const trapLeaf = (owner, leaf) => {
                    try {
                        Object.defineProperty(owner, leaf, {get: function() { return value; },set: function() {},configurable: true,enumerable: true});
                    } catch {}
                };
                const trapChain = (owner, idx) => {
                    if (idx >= parts.length - 1) { trapLeaf(owner, parts[parts.length - 1]); return; }
                    const key = parts[idx];
                    let cur = null;
                    try { cur = owner[key]; } catch { cur = null; }
                    if (cur == null || (typeof cur !== 'object' && typeof cur !== 'function')) {
                        try { owner[key] = {}; } catch {}
                        try { cur = owner[key]; } catch { return; }
                    }
                    trapChain(cur, idx + 1);
                    let stored = cur;
                    try {
                        Object.defineProperty(owner, key, {
                            get: function() { return stored; },
                            set: function(v) {
                                stored = v;
                                if (v !== null && (typeof v === 'object' || typeof v === 'function')) {
                                    try { trapChain(stored, idx + 1); } catch {}
                                }
                            },
                            configurable: true, enumerable: true
                        });
                    } catch {}
                };
                try { trapChain(window, 0); } catch {}
            });
            this.register('set', this.registeredScriptlets.get('set-constant'));
            this.register('hide', function(selector) {
                if (!selector) return;
                const style = document.createElement('style');
                style.textContent = `${selector} { display: none !important; visibility: hidden !important; opacity: 0 !important; pointer-events: none !important; }`;
                style.setAttribute('data-adsecurity', 'true');
                document.head.appendChild(style);
                document.querySelectorAll(selector).forEach(el => {el.style.display = 'none';el.style.visibility = 'hidden';el.style.opacity = '0';el.style.pointerEvents = 'none';});
            });
            this.register('remove', function(selector) {
                if (!selector) return;
                const removeElements = () => {document.querySelectorAll(selector).forEach(el => el.remove());};
                removeElements();
                watchDOM(() => removeElements());
            });
            this.register('remove-node', this.registeredScriptlets.get('remove'));
            this.register('remove-attr', function(selector, attr) {
                if (!selector || !attr) return;
                document.querySelectorAll(selector).forEach(el => {if (el.hasAttribute(attr)) el.removeAttribute(attr);});
            });
            this.register('remove-class', function(selector, className) {
                if (!selector || !className) return;
                document.querySelectorAll(selector).forEach(el => el.classList.remove(className));
            });
            this.register('noop', function(){});
            this.register('noopjs', function(){});
            this.register('noopjson', function(){});
            this.register('noop-fetch', function() {
                window.fetch = function() {return Promise.resolve(new Response('', { status: 200 }));};
            });
            this.register('noop-xhr', function() {
                const original = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
                    if (url.includes('ad') || url.includes('analytics') || url.includes('tracking')) {return;}
                    return original.call(this, method, url, async, user, password);
                };
            });
            this.register('noop-image', function() {
                const originalDescriptor = Object.getOwnPropertyDescriptor(Image.prototype, 'src');
                if (originalDescriptor) {
                    const originalSet = originalDescriptor.set;
                    Object.defineProperty(Image.prototype, 'src', {
                        get: function() {return originalDescriptor.get ? originalDescriptor.get.call(this) : '';},
                        set: function(value) {
                            const urlStr = String(value || '');
                            if (urlStr.includes('ad') || urlStr.includes('analytics') || urlStr.includes('tracking') || urlStr.includes('doubleclick') || urlStr.includes('googlead') || urlStr.includes('facebook')) {return;}
                            if (originalSet) {originalSet.call(this, value);}
                        },
                        configurable: true
                    });
                }
            });
            this.register('prevent-addEventListener', function(type, pattern) {
                const original = EventTarget.prototype.addEventListener;
                const reType = pattern ? new RegExp(pattern) : null;
                EventTarget.prototype.addEventListener = function(type2, listener, options) {
                    if (type2 === type || (reType && reType.test(type2))) {return;}
                    return original.call(this, type2, listener, options);
                };
            });
            this.register('prevent-fetch', function(pattern) {
                if (!pattern) return;
                const original = window.fetch;
                window.fetch = function(url, options) {
                    const urlStr = typeof url === 'string' ? url : (url.url || '');
                    if (urlStr.includes(pattern)) {return Promise.resolve(new Response('', { status: 200 }));}
                    return original.call(this, url, options);
                };
            });
            this.register('prevent-xhr', function(pattern) {
                if (!pattern) return;
                const original = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
                    if (url.includes(pattern)) {this.abort();return;}
                    return original.call(this, method, url, async, user, password);
                };
            });
            this.register('prevent-websocket', function(pattern) {
                if (!pattern) return;
                const original = window.WebSocket;
                window.WebSocket = function(url, protocols) {
                    if (url.includes(pattern)) {throw new Error('WebSocket blocked by AdSecurity');}
                    return new original(url, protocols);
                };
            });
            this.register('prevent-window-open', function(pattern) {
                const original = window.open;
                window.open = function(url, ...args) {
                    const urlStr = String(url || '');
                    if (!pattern) return null;
                    try {if (new RegExp(pattern).test(urlStr)) return null;} catch {if (urlStr.includes(pattern)) return null;}
                    return original.call(this, url, ...args);
                };
            });
            this.register('no-window-open-if', this.registeredScriptlets.get('prevent-window-open'));
            this.register('nowoif', this.registeredScriptlets.get('prevent-window-open'));
            this.register('window.open-defuser', this.registeredScriptlets.get('prevent-window-open'));
            this.register('setTimeout-defuser', function(condition) {
                const original = window.setTimeout;
                window.setTimeout = function(fn, delay, ...args) {
                    if (condition) {
                        try {const fnStr = fn.toString();if (fnStr.includes(condition)) return 0;} catch {}
                    }
                    return original.call(this, fn, delay, ...args);
                };
            });
            this.register('setInterval-defuser', function(condition) {
                const original = window.setInterval;
                window.setInterval = function(fn, delay, ...args) {
                    if (condition) {
                        try {const fnStr = fn.toString();if (fnStr.includes(condition)) return 0;} catch {}
                    }
                    return original.call(this, fn, delay, ...args);
                };
            });
            this.register('prevent-setTimeout', this.registeredScriptlets.get('setTimeout-defuser'));
            this.register('prevent-setInterval', this.registeredScriptlets.get('setInterval-defuser'));
            this.register('no-setTimeout-if', this.registeredScriptlets.get('setTimeout-defuser'));
            this.register('no-setInterval-if', this.registeredScriptlets.get('setInterval-defuser'));
            this.register('alert-buster', function() {
                window.alert = function() {};
                window.confirm = function() { return false; };
                window.prompt = function() { return null; };
            });
            this.register('nowebrtc', function() {
                const noop = function() {};
                noop.prototype = {};
                ['RTCPeerConnection', 'webkitRTCPeerConnection', 'mozRTCPeerConnection'].forEach(name => {
                    try {Object.defineProperty(window, name, {get: () => noop,set: () => {},configurable: true});} catch {}
                });
            });
            this.register('prevent-canvas', function(type) {
                const orig = HTMLCanvasElement.prototype.getContext;
                HTMLCanvasElement.prototype.getContext = function(ct, ...args) {
                    if (!type || ct === type) return null;
                    return orig.call(this, ct, ...args);
                };
            });
            this.register('disable-newtab-links', function() {
                document.addEventListener('click', function(e) {
                    const el = e.target.closest('a[target]');
                    if (el && (el.target === '_blank' || el.target === '_new')) {el.removeAttribute('target');}
                }, true);
            });
            this.register('abort-on-property-read', function(prop) {
                if (!prop) return;
                try {
                    let aborted = false;
                    const parts = prop.split('.');
                    let target = window;
                    for (let i = 0; i < parts.length - 1; i++) {
                        if (target[parts[i]] === undefined) return;
                        target = target[parts[i]];
                    }
                    const last = parts[parts.length - 1];
                    Object.defineProperty(target, last, {
                        get: function() {
                            if (!aborted) {aborted = true;console.warn('Aborted on property read:', prop);throw new Error('Aborted by AdSecurity');}
                            return undefined;
                        },
                        set: function() {},
                        configurable: true
                    });
                } catch {}
            });
            this.register('abort-on-property-write', function(prop) {
                if (!prop) return;
                try {
                    const parts = prop.split('.');
                    let target = window;
                    for (let i = 0; i < parts.length - 1; i++) {
                        if (target[parts[i]] === undefined) return;
                        target = target[parts[i]];
                    }
                    const last = parts[parts.length - 1];
                    Object.defineProperty(target, last, {
                        get: function() { return undefined; },
                        set: function() {console.warn('Aborted on property write:', prop);throw new Error('Aborted by AdSecurity');},
                        configurable: true
                    });
                } catch {}
            });
            this.register('abort-on-stack-trace', function(prop, stack) {
                if (!prop) return;
                try {
                    const parts = prop.split('.');
                    let target = window;
                    for (let i = 0; i < parts.length - 1; i++) {
                        if (target[parts[i]] === undefined) return;
                        target = target[parts[i]];
                    }
                    const last = parts[parts.length - 1];
                    Object.defineProperty(target, last, {
                        get: function() {
                            if (new Error().stack.includes(stack || '')) {console.warn('Aborted on stack trace:', prop);throw new Error('Aborted by AdSecurity');}
                            return undefined;
                        },
                        set: function() {},
                        configurable: true
                    });
                } catch {}
            });
            this.register('adjust-setTimeout', function(needle, delay, boost) {
                const factor = parseFloat(boost) || 0.02;
                const matchDelay = delay ? parseInt(delay) : null;
                const orig = window.setTimeout;
                window.setTimeout = function(fn, ms, ...args) {
                    if (needle) {
                        try {
                            const s = typeof fn === 'function' ? fn.toString() : String(fn);
                            if (s.includes(needle) && (!matchDelay || Math.abs(ms - matchDelay) < matchDelay)) {ms = Math.max(1, Math.round(ms * factor));}
                        } catch {}
                    }
                    return orig.call(this, fn, ms, ...args);
                };
            });
            this.register('adjust-setInterval', function(needle, delay, boost) {
                const factor = parseFloat(boost) || 0.02;
                const matchDelay = delay ? parseInt(delay) : null;
                const orig = window.setInterval;
                window.setInterval = function(fn, ms, ...args) {
                    if (needle) {
                        try {
                            const s = typeof fn === 'function' ? fn.toString() : String(fn);
                            if (s.includes(needle) && (!matchDelay || Math.abs(ms - matchDelay) < matchDelay)) {ms = Math.max(1, Math.round(ms * factor));}
                        } catch {}
                    }
                    return orig.call(this, fn, ms, ...args);
                };
            });
            this.register('json-prune', function(propsToRemove, needleInHaystack) {
                if (!propsToRemove) return;
                let paths = [];
                let needle = null;
                const args = propsToRemove.split(/\s+/).filter(a => a);
                for (const arg of args) {if (arg === 'important') continue;paths.push(arg);}
                if (needleInHaystack && needleInHaystack !== 'important') {needle = needleInHaystack;}
                paths = paths.filter(p => p && p !== 'important');
                if (!paths.length) return;
                const pruneObject = (obj, pathParts) => {
                    if (!obj || typeof obj !== 'object') return obj;
                    const current = pathParts[0];
                    if (current === '[]' || current === '[-]') {
                        const rest = pathParts.slice(1);
                        if (Array.isArray(obj)) {
                            // `[-]` + devam yolu: SADECE son elemana uygula (uBO semantiği).
                            // Eskiden yolun geri kalanı yok sayılıp tüm son eleman siliniyordu.
                            if (current === '[-]') {
                                if (!obj.length) return obj;
                                if (!rest.length) return obj.slice(0, -1);
                                const out = obj.slice();
                                out[out.length - 1] = pruneObject(obj[obj.length - 1], rest);
                                return out;
                            }
                            return obj.map(item => pruneObject(item, rest));
                        }
                        return obj;
                    }
                    if (pathParts.length === 1) {
                        if (Array.isArray(obj)) {
                            return obj.map(item => {
                                if (item && typeof item === 'object') {const newItem = { ...item };delete newItem[current];return newItem;}
                                return item;
                            });
                        }
                        const newObj = { ...obj };
                        delete newObj[current];
                        return newObj;
                    }
                    const rest = pathParts.slice(1);
                    if (Array.isArray(obj)) {return obj.map(item => pruneObject(item, pathParts));}
                    if (obj[current] && typeof obj[current] === 'object') {
                        const newObj = { ...obj };
                        newObj[current] = pruneObject(obj[current], rest);
                        return newObj;
                    }
                    return obj;
                };
                // Birden fazla path boşlukla ayrılır; HER biri ayrı uygulanır.
                // Eskiden tüm segmentler tek zincir gibi birleştiriliyordu
                // (çok path'li kurallarda hiçbir şey budanmıyordu).
                const pathList = paths.map(p => p.replace(/\.\[\]/g, '.[]').replace(/\.\[-\]/g, '.[-]').split(/\./).map(part => {
                    if (part === '[]' || part === '[-]') return part;
                    if (part.endsWith('[]')) return part.slice(0, -2);
                    if (part.endsWith('[-]')) return part.slice(0, -3);
                    return part;
                }).filter(Boolean));
                const pruneAll = (obj) => {
                    let out = obj;
                    for (const segs of pathList) {
                        if (!segs.length) continue;
                        try { out = pruneObject(out, segs); } catch {}
                    }
                    return out;
                };
                const originalParse = JSON.parse;
                JSON.parse = function(text, reviver) {
                    const result = originalParse.call(this, text, reviver);
                    if (needle && typeof text === 'string' && !text.includes(needle)) return result;
                    try {return pruneAll(result);} catch {return result;}
                };
                const originalFetch = window.fetch;
                window.fetch = function(...args) {
                    return originalFetch.apply(this, args).then(response => {
                        const clone = response.clone();
                        return clone.text().then(text => {
                            if (needle && !text.includes(needle)) return response;
                            try {
                                const data = JSON.parse(text);
                                const pruned = pruneAll(data);
                                if (pruned !== data) {
                                    return new Response(JSON.stringify(pruned), {status: response.status,statusText: response.statusText,headers: response.headers});
                                }
                            } catch {}
                            return response;
                        }).catch(() => response);
                    });
                };
            });
            this.register('xml-prune', function(selector) {
                if (!selector) return;
                const prune = function(node) {
                    if (!node || node.nodeType !== 1) return;
                    const children = Array.from(node.children);
                    for (const child of children) {
                        if (child.matches && child.matches(selector)) {child.remove();} else {prune(child);}
                    }
                };
                watchDOM(function() {if (document.body) prune(document.body);});
                if (document.body) prune(document.body);
            });
            this.register('m3u-prune', function(pattern, urlFilter) {
                if (!pattern) return;
                let searchRe;
                try { searchRe = new RegExp(pattern, 'm'); } catch {searchRe = new RegExp(pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'm');}
                const urlTest = urlFilter ? (u) => {try { return new RegExp(urlFilter).test(u); } catch { return u.includes(urlFilter); }} : (u) => /\.m3u8?(\?|$)/i.test(u);
                const prune = (text) => text.split('\n').filter(line => {searchRe.lastIndex = 0;return !searchRe.test(line);}).join('\n');
                const orig = window.fetch;
                window.fetch = function(input, opts) {
                    const urlStr = typeof input === 'string' ? input : (input && input.url) || '';
                    if (!urlTest(urlStr)) return orig.apply(this, arguments);
                    return orig.apply(this, arguments).then(r => r.text().then(text => {
                        return new Response(prune(text), {status: r.status,statusText: r.statusText,headers: r.headers});
                    }).catch(() => r));
                };
            });
            this.register('prevent-innerHTML', function(selector, pattern) {
                if (!selector) return;
                const orig = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
                if (!orig) return;
                const rePattern = pattern ? new RegExp(pattern) : null;
                Object.defineProperty(Element.prototype, 'innerHTML', {
                    get: function() { return orig.get.call(this); },
                    set: function(value) {
                        if (this.matches(selector) && (!rePattern || rePattern.test(value))) {return;}
                        orig.set.call(this, value);
                    },
                    configurable: true
                });
            });
            this.register('prevent-requestAnimationFrame', function(needle) {
                const orig = window.requestAnimationFrame;
                const reNeedle = needle ? new RegExp(needle) : null;
                window.requestAnimationFrame = function(callback) {
                    if (reNeedle) {
                        try {const fnStr = callback.toString();if (reNeedle.test(fnStr)) return 0;} catch {}
                    }
                    return orig.call(this, callback);
                };
            });
            this.register('noeval-if', function(pattern) {
                if (!pattern) return;
                const orig = window.eval;
                const rePattern = new RegExp(pattern);
                window.eval = function(code) {
                    const s = String(code);
                    if (rePattern.test(s)) return;
                    return orig.call(this, code);
                };
            });
            this.register('abort-current-script', function(prop, pattern) {
                if (!prop) return;
                document.addEventListener('beforescriptexecute', function(e) {
                    const text = e.target && e.target.textContent;
                    if (!text || !text.includes(prop)) return;
                    if (pattern) {
                        try {if (!new RegExp(pattern).test(text)) return;} catch {if (!text.includes(pattern)) return;}
                    }
                    e.preventDefault();
                    e.stopPropagation();
                }, true);
            });
            this.register('prevent-element', function(selector) {
                if (!selector) return;
                watchDOM(function(mutations) {
                    for (const mutation of mutations) {
                        for (const node of mutation.addedNodes) {
                            if (node.nodeType === 1) {
                                if (node.matches && node.matches(selector)) node.remove();
                                if (node.querySelectorAll) {node.querySelectorAll(selector).forEach(el => el.remove());}
                            }
                        }
                    }
                });
                document.querySelectorAll(selector).forEach(el => el.remove());
            });
            this.register('prevent-event', function(eventType, selector) {
                if (!eventType) return;
                document.addEventListener(eventType, function(e) {
                    if (selector && e.target && e.target.matches) {
                        if (e.target.matches(selector) || e.target.closest(selector)) {e.preventDefault();e.stopPropagation();return false;}
                    } else {e.preventDefault();e.stopPropagation();return false;}
                }, true);
            });
            this.register('spoof-css', function(selector, prop, value) {
                if (!selector || !prop) return;
                const orig = window.getComputedStyle;
                window.getComputedStyle = function(el, pseudo) {
                    const result = orig.call(this, el, pseudo);
                    try {
                        if (el && el.matches && el.matches(selector)) {
                            return new Proxy(result, {
                                get(t, p) {
                                    if (p === 'getPropertyValue') {return (n) => n === prop ? value : t.getPropertyValue(n);}
                                    if (p === prop) return value;
                                    const v = t[p];
                                    return typeof v === 'function' ? v.bind(t) : v;
                                }
                            });
                        }
                    } catch {}
                    return result;
                };
            });
            this.register('window.name-defuser', function() {
                window.name = '';
                try {Object.defineProperty(window, 'name', {get: () => '',set: () => {},configurable: true});} catch {}
            });
            this.register('prevent-refresh', function() {
                const block = () => document.querySelectorAll('meta[http-equiv="refresh"]').forEach(el => el.remove());
                block();
                watchDOM(block);
            });
            this.register('close-window', function(pattern) {
                if (!pattern) { window.close(); return; }
                const url = window.location.href;
                try {if (new RegExp(pattern).test(url)) window.close();} catch {if (url.includes(pattern)) window.close();}
            });
            this.register('overlay-buster', function() {
                const style = document.createElement('style');
                style.textContent = '* { overflow: auto !important; }';
                style.setAttribute('data-adsecurity', 'true');
                (document.head || document.documentElement).appendChild(style);
                const restore = () => {
                    if (!document.body) return;
                    document.body.style.removeProperty('overflow');
                    document.documentElement.style.removeProperty('overflow');
                };
                restore();
                new MutationObserver(restore).observe(document.documentElement, {attributes: true,attributeFilter: ['style', 'class'],subtree: true});
            });
            this.register('href-sanitizer', function(selector, pattern, replacement) {
                if (!selector) return;
                document.querySelectorAll(selector).forEach(el => {if (el.href) {el.href = el.href.replace(new RegExp(pattern, 'g'), replacement || '');}});
            });
            this.register('url-sanitizer', function(pattern, replacement) {
                if (!pattern) return;
                const currentUrl = new URL(window.location.href);
                const newPath = currentUrl.pathname.replace(new RegExp(pattern, 'g'), replacement || '');
                if (newPath !== currentUrl.pathname) {currentUrl.pathname = newPath;window.history.replaceState({}, '', currentUrl.href);}
            });
            this.register('set-cookie', function(name, value, path) {
                if (!name) return;
                document.cookie = `${name}=${value || ''}; path=${path || '/'}`;
            });
            this.register('remove-cookie', function(name) {
                if (!name) return;
                const exp = 'expires=Thu, 01 Jan 1970 00:00:00 GMT';
                document.cookie = `${name}=; ${exp}; path=/`;
                document.cookie = `${name}=; ${exp}; path=/; domain=${window.location.hostname}`;
            });
            this.register('set-local-storage-item', function(key, value) {
                if (!key) return;
                try { localStorage.setItem(key, value || ''); } catch {}
            });
            this.register('set-session-storage-item', function(key, value) {
                if (!key) return;
                try { sessionStorage.setItem(key, value || ''); } catch {}
            });
            this.register('inject-css', function(css) {
                if (!css) return;
                const style = document.createElement('style');
                style.textContent = css;
                style.setAttribute('data-adsecurity', 'true');
                document.head.appendChild(style);
            });
            this.register('inject-script', function(code) {
                if (!code) return;
                const script = document.createElement('script');
                script.textContent = code;
                script.setAttribute('data-adsecurity', 'true');
                document.documentElement.appendChild(script);
                script.remove();
            });
            function toRegExp(pattern, defaultFlags) {
                if (!pattern) return null;
                // `/kaynak/bayrak` literali desteklenir; değilse düz metin olarak derlenir.
                // (Örn. rpnt kuralındaki `/(\(function...)/` deseni ancak böyle eşleşir.)
                if (pattern.length > 2 && pattern[0] === '/' && pattern.lastIndexOf('/') > 0) {
                    try { return new RegExp(pattern.slice(1, pattern.lastIndexOf('/')), pattern.slice(pattern.lastIndexOf('/') + 1) || defaultFlags); } catch {}
                }
                try { return new RegExp(pattern, defaultFlags); } catch { return null; }
            }
            this.register('replace-node-text', function(selector, pattern, replacement, ...extraArgs) {
                if (!selector) return;
                const extra = {};
                for (let i = 0; i + 1 < extraArgs.length; i += 2) { if (extraArgs[i] !== undefined) extra[String(extraArgs[i])] = extraArgs[i + 1]; }
                const rePattern = toRegExp(pattern, 'g');
                if (!rePattern) return;
                const sedCount = extra.sedCount !== undefined ? parseInt(extra.sedCount, 10) : 0;
                const excludeList = extra.excludes ? String(extra.excludes).split(/\s*\|\s*|,/).filter(Boolean) : [];
                let condRe = null; let condStr = null;
                if (extra.condition !== undefined && extra.condition !== '') {
                    const c = String(extra.condition);
                    if (c.length > 2 && c[0] === '/' && c.lastIndexOf('/') > 0) {
                        try { condRe = new RegExp(c.slice(1, c.lastIndexOf('/')), c.slice(c.lastIndexOf('/') + 1) || ''); } catch { condStr = c; }
                    } else { condStr = c; }
                }
                const applyOne = (el) => {
                    if (!el || !el.textContent) return;
                    const text = el.textContent;
                    if (condRe && !condRe.test(text)) return;
                    if (condStr && !text.includes(condStr)) return;
                    for (const ex of excludeList) { if (ex && text.includes(ex)) return; }
                    try {
                        if (sedCount > 0) {
                            let out = text;
                            const single = new RegExp(rePattern.source, (rePattern.flags || '').replace('g', ''));
                            for (let k = 0; k < sedCount; k++) {
                                if (!single.test(out)) break;
                                single.lastIndex = 0;
                                out = out.replace(single, replacement || '');
                            }
                            if (out !== text) el.textContent = out;
                        } else {
                            rePattern.lastIndex = 0;
                            const out = text.replace(rePattern, replacement || '');
                            if (out !== text) el.textContent = out;
                        }
                    } catch {}
                    rePattern.lastIndex = 0;
                };
                const applyAll = (root) => {
                    try { root.querySelectorAll(selector).forEach(applyOne); } catch {}
                };
                applyAll(document);
                watchDOM(ms2 => {
                    for (const m of ms2) { for (const n of m.addedNodes) {
                        if (n.nodeType !== 1) continue;
                        if (n.matches && n.matches(selector)) applyOne(n);
                        if (n.querySelectorAll) try { n.querySelectorAll(selector).forEach(applyOne); } catch {}
                    }}
                });
            });
            this.register('remove-node-text', function(nodeName, ...patternParts) {
                if (!nodeName) return;
                const reNode = new RegExp(nodeName, 'i');
                // Virgül içeren desenler argüman bölmede parçalanır (örn. window,"fetch"
                // -> ["window","fetch"]); parçaları AND koşulu say: hepsi eşleşirse sil.
                const pats = patternParts.filter(p => p !== undefined && p !== '').map(p => toRegExp(p, 'gms') || null);
                const clean = (node) => {
                    if (!node || !reNode.test(node.nodeName)) return;
                    const text = node.textContent || '';
                    if (!pats.length) { node.textContent = ''; return; }
                    let allMatch = true;
                    for (const re of pats) {
                        if (!re) { allMatch = false; break; }
                        re.lastIndex = 0;
                        if (!re.test(text)) { allMatch = false; break; }
                        re.lastIndex = 0;
                    }
                    if (!allMatch) return;
                    // Tüm parça eşleşti: düğüm metnini temizle (uBO rmnt davranışı)
                    if (pats.length === 1) {
                        node.textContent = text.replace(pats[0], '');
                        pats[0].lastIndex = 0;
                    } else {
                        node.textContent = '';
                    }
                };
                const sweep = (root) => {
                    try { root.querySelectorAll(nodeName).forEach(clean); } catch {}
                };
                sweep(document);
                watchDOM(ms2 => {
                    for (const m of ms2) { for (const n of m.addedNodes) {
                        if (n.nodeType !== 1) continue;
                        clean(n);
                        if (n.querySelectorAll) try { n.querySelectorAll(nodeName).forEach(clean); } catch {}
                    }}
                });
            });
            this.register('noopmp4-1s', function() {
                const noopData = 'data:video/mp4;base64,AAAAIGZ0eXBpc29tAAACAGlzb21pc28yYXZjMW1wNDEAAAAIZnJlZQAAAQxtZGF0AAAAMgAAACh3cnZrbG9n';
                const originalFetch = window.fetch;
                window.fetch = function(input, options) {
                    const urlStr = typeof input === 'string' ? input : (input && input.url) || '';
                    if (urlStr.includes('get_video') && urlStr.includes('source=youtube')) {
                        return Promise.resolve(new Response(noopData, {status: 200,headers: { 'Content-Type': 'video/mp4' }}));
                    }
                    return originalFetch.apply(this, arguments);
                };
            });
            this.register('nano-stb', function(needle, delay, boost) {
                const needleStr = needle || '';
                const matchDelay = delay ? parseInt(delay, 10) : null;
                const factor = parseFloat(boost) || 0.001;
                const orig = window.setTimeout;
                window.setTimeout = function(fn, ms, ...args) {
                    try {
                        const fnStr = typeof fn === 'function' ? fn.toString() : String(fn);
                        if (fnStr.includes(needleStr) && (!matchDelay || ms === matchDelay)) {ms = Math.max(1, Math.round(ms * factor));}
                    } catch {}
                    return orig.call(this, fn, ms, ...args);
                };
            });
            this.register('redirect-noopmp4-1s', this.registeredScriptlets.get('noopmp4-1s'));
            this.register('rmnt', this.registeredScriptlets.get('remove-node-text'));
            this.register('rpnt', this.registeredScriptlets.get('replace-node-text'));
            // json-prune çekirdeği: path listesi + pruneAll + url testi paylaşılır.
            const buildPrunePathList = (propsToRemove) => {
                const paths = String(propsToRemove || '').split(/\s+/).filter(a => a && a !== 'important');
                return paths.map(p => p.replace(/\.\[\]/g, '.[]').replace(/\.\[-\]/g, '.[-]').split(/\./).map(part => {
                    if (part === '[]' || part === '[-]') return part;
                    if (part.endsWith('[]')) return part.slice(0, -2);
                    if (part.endsWith('[-]')) return part.slice(0, -3);
                    return part;
                }).filter(s => s && s.length));
            };
            const pruneObjectWith = (obj, pathParts) => {
                if (!obj || typeof obj !== 'object') return obj;
                const current = pathParts[0];
                if (pathParts.length === 1) {
                    if (Array.isArray(obj)) {
                        return obj.map(item => {
                            if (item && typeof item === 'object') { const ni = { ...item }; delete ni[current]; return ni; }
                            return item;
                        });
                    }
                    const no = { ...obj }; delete no[current]; return no;
                }
                const rest = pathParts.slice(1);
                if (Array.isArray(obj)) { return obj.map(item => pruneObjectWith(item, pathParts)); }
                if (obj[current] && typeof obj[current] === 'object') {
                    const no = { ...obj }; no[current] = pruneObjectWith(obj[current], rest); return no;
                }
                return obj;
            };
            const buildPruneAll = (pathList) => (obj) => {
                let out = obj;
                for (const segs of pathList) { try { out = pruneObjectWith(out, segs); } catch {} }
                return out;
            };
            const buildPruneUrlTest = (urlFilter, extraArgs) => {
                const extra = {};
                for (let i = 0; i + 1 < (extraArgs || []).length; i += 2) { if (extraArgs[i] !== undefined) extra[String(extraArgs[i])] = extraArgs[i + 1]; }
                let pat = urlFilter;
                if (extra.propsToMatch !== undefined && extra.propsToMatch !== '') pat = extra.propsToMatch;
                if (!pat) return () => true;
                pat = String(pat);
                if (pat.length > 2 && pat[0] === '/' && pat.lastIndexOf('/') > 0) {
                    try { const re = new RegExp(pat.slice(1, pat.lastIndexOf('/')), pat.slice(pat.lastIndexOf('/') + 1)); return (u) => re.test(u); } catch {}
                }
                if (pat.includes('*')) {
                    try { const re = new RegExp(pat.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')); return (u) => re.test(u); } catch {}
                }
                return (u) => String(u || '').includes(pat.replace(/^\/|\/$/g, ''));
            };
            this.register('json-prune-fetch-response', function(propsToRemove, needleArg, urlFilter, ...extraArgs) {
                if (!propsToRemove) return;
                const needle = (needleArg && needleArg !== 'important') ? String(needleArg) : null;
                const pruneAll = buildPruneAll(buildPrunePathList(propsToRemove));
                const urlTest = buildPruneUrlTest(urlFilter, extraArgs);
                const originalFetch = window.fetch;
                window.fetch = function(input, ...rest) {
                    const urlStr = typeof input === 'string' ? input : (input && input.url) || '';
                    if (!urlTest(urlStr)) return originalFetch.apply(this, [input, ...rest]);
                    return originalFetch.apply(this, [input, ...rest]).then(response => {
                        const clone = response.clone();
                        return clone.text().then(text => {
                            if (needle && !text.includes(needle)) return response;
                            try {
                                const data = JSON.parse(text);
                                const pruned = pruneAll(data);
                                if (pruned !== data) {
                                    return new Response(JSON.stringify(pruned), {status: response.status, statusText: response.statusText, headers: response.headers});
                                }
                            } catch {}
                            return response;
                        }).catch(() => response);
                    });
                };
            });
            this.register('json-prune-xhr-response', function(propsToRemove, needleArg, urlFilter, ...extraArgs) {
                if (!propsToRemove) return;
                const needle = (needleArg && needleArg !== 'important') ? String(needleArg) : null;
                const pruneAll = buildPruneAll(buildPrunePathList(propsToRemove));
                const urlTest = buildPruneUrlTest(urlFilter, extraArgs);
                const OriginalXHR = window.XMLHttpRequest;
                function PatchedXHR() {
                    const xhr = new OriginalXHR();
                    let _url = '';
                    const origOpen = xhr.open.bind(xhr);
                    const origSend = xhr.send.bind(xhr);
                    xhr.open = function(method, url, ...rest) { _url = typeof url === 'string' ? url : String(url); return origOpen(method, url, ...rest); };
                    xhr.send = function(...args) {
                        if (!urlTest(_url)) return origSend(...args);
                        xhr.addEventListener('readystatechange', function() {
                            if (this.readyState !== 4) return;
                            try {
                                const text = this.responseText;
                                if (!text || (needle && !text.includes(needle))) return;
                                const data = JSON.parse(text);
                                const pruned = pruneAll(data);
                                const newText = JSON.stringify(pruned);
                                if (newText !== text) {
                                    Object.defineProperty(this, 'response', {value: newText, configurable: true, writable: true});
                                    Object.defineProperty(this, 'responseText', {value: newText, configurable: true, writable: true});
                                }
                            } catch {}
                        });
                        return origSend(...args);
                    };
                    return xhr;
                }
                PatchedXHR.prototype = OriginalXHR.prototype;
                window.XMLHttpRequest = PatchedXHR;
            });
        }
        registerTrustedScriptlets() {
            this.register('trusted-set-constant', this.registeredScriptlets.get('set-constant'));
            this.register('trusted-set', this.registeredScriptlets.get('set-constant'));
            this.register('trusted-replace-argument', function(fnPath, argIndex, newValue) {
                if (!fnPath) return;
                // Ekstra anahtarlar: `condition, <metin>` (eşleşmezse dokunma),
                // `this` konumu (hedef `this` değeridir). `repl:/a/b/` değeri
                // toptan değiştirme değil regex-dönüşümüdür.
                const extra = Array.prototype.slice.call(arguments, 3);
                let condition = null;
                for (let i = 0; i + 1 < extra.length; i += 2) {
                    if (extra[i] === 'condition' && extra[i + 1] !== undefined) condition = String(extra[i + 1]);
                }
                let replRe = null, replTo = '';
                if (typeof newValue === 'string' && newValue.startsWith('repl:')) {
                    // `repl:/kaynak/hedef/bayrak` — sondaki `/` ayraçtır;
                    // kaynak içindeki ilk kaçışsız `/` kaynak/hedef sınırıdır.
                    const body = newValue.slice(5);
                    if (body.length > 2 && body[0] === '/' && body.lastIndexOf('/') > 0) {
                        try {
                            const inner = body.slice(1, body.lastIndexOf('/'));
                            const flags = body.slice(body.lastIndexOf('/') + 1) || 'g';
                            let sep = -1, esc = false;
                            for (let k = 0; k < inner.length; k++) {
                                const c = inner[k];
                                if (esc) { esc = false; continue; }
                                if (c === '\\') { esc = true; continue; }
                                if (c === '/') { sep = k; break; }
                            }
                            if (sep !== -1) {
                                replRe = new RegExp(inner.slice(0, sep), flags);
                                replTo = inner.slice(sep + 1);
                            } else {
                                replRe = new RegExp(inner, flags);
                                replTo = '';
                            }
                        } catch { replRe = null; }
                    }
                }
                const parts = fnPath.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const fnName = parts[parts.length - 1];
                if (typeof target[fnName] !== 'function') return;
                const originalFn = target[fnName];
                const useThis = String(argIndex) === 'this';
                const index = useThis ? -1 : (parseInt(argIndex) || 0);
                target[fnName] = function(...args) {
                    if (condition) {
                        // `this` konumu kullanılıyorsa koşul `this` değerinde aranır
                        // (kural 5'teki gibi: ayraç argümanında değil, bölünen
                        // URL'in kendisinde), yoksa argümanlarda.
                        let hay = '';
                        try {
                            hay = useThis ? String(this) : args.map(a => String(a)).join(' ');
                        } catch {}
                        let condRe = null;
                        try { condRe = new RegExp(condition); } catch {}
                        if (condRe ? !condRe.test(hay) : hay.indexOf(condition) === -1) {
                            return originalFn.apply(this, args);
                        }
                    }
                    const transform = (v) => {
                        if (replRe && typeof v === 'string') {
                            try { return v.replace(replRe, replTo); } catch { return v; }
                        }
                        return newValue;
                    };
                    if (useThis) {
                        let thisArg = this;
                        try { thisArg = transform(String(this)); } catch {}
                        return originalFn.apply(thisArg, args);
                    }
                    if (args.length > index && args[index] !== undefined) {args[index] = transform(args[index]);}
                    return originalFn.apply(this, args);
                };
            });
            this.register('trusted-suppress-native-method', function(methodPath) {
                if (!methodPath) return;
                const parts = methodPath.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const methodName = parts[parts.length - 1];
                if (typeof target[methodName] !== 'function') return;
                Object.defineProperty(target, methodName, {value: function() { return undefined; },writable: false,configurable: false});
            });
            this.register('trusted-call-renderer', function(rendererPath, condition) {
                if (!rendererPath) return;
                const parts = rendererPath.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const rendererName = parts[parts.length - 1];
                if (typeof target[rendererName] !== 'function') return;
                const originalRenderer = target[rendererName];
                target[rendererName] = function(...args) {
                    if (condition) {
                        try {if (JSON.stringify(args).includes(condition)) return;} catch {}
                    }
                    return originalRenderer.apply(this, args);
                };
            });
            this.register('trusted-click-element', function(selector, delay) {
                if (!selector) return;
                const timeout = parseInt(delay) || 0;
                setTimeout(() => {
                    const element = document.querySelector(selector);
                    if (element && element.click) element.click();
                }, timeout);
            });
            this.register('trusted-create-element', function(tagName, attributes, content) {
                if (!tagName) return;
                const element = document.createElement(tagName);
                if (attributes) {
                    try {
                        const attrs = JSON.parse(attributes);
                        for (const [key, value] of Object.entries(attrs)) {element.setAttribute(key, value);}
                    } catch {}
                }
                if (content) {element.textContent = content;}
                document.documentElement.appendChild(element);
            });
            this.register('trusted-set-cookie', function(name, value, options) {
                if (!name) return;
                let cookieStr = `${name}=${value || ''}`;
                if (options) {
                    const opts = options.split(',').map(o => o.trim());
                    for (const opt of opts) {cookieStr += `; ${opt}`;}
                }
                document.cookie = cookieStr;
            });
            this.register('trusted-set-local-storage-item', function(key, value) {
                if (!key) return;
                try { localStorage.setItem(key, value || ''); } catch {}
            });
            this.register('trusted-set-session-storage-item', function(key, value) {
                if (!key) return;
                try { sessionStorage.setItem(key, value || ''); } catch {}
            });
            this.register('trusted-remove-parameter', function(paramName) {
                if (!paramName) return;
                const url = new URL(window.location.href);
                url.searchParams.delete(paramName);
                if (url.href !== window.location.href) {window.history.replaceState({}, '', url.href);}
            });
            this.register('trusted-prune-inbound-object', function(propPath) {
                if (!propPath) return;
                const pathParts = propPath.split('.').filter(p => p);
                const pruneObject = (obj) => {
                    if (!obj || typeof obj !== 'object') return obj;
                    const current = pathParts[0];
                    if (pathParts.length === 1) {
                        if (Array.isArray(obj)) {
                            return obj.map(item => {
                                if (item && typeof item === 'object') {const newItem = { ...item };delete newItem[current];return newItem;}
                                return item;
                            });
                        }
                        const newObj = { ...obj };
                        delete newObj[current];
                        return newObj;
                    }
                    const rest = pathParts.slice(1);
                    if (Array.isArray(obj)) {return obj.map(item => pruneObject(item));}
                    if (obj[current] && typeof obj[current] === 'object') {
                        const newObj = { ...obj };
                        newObj[current] = pruneObject(obj[current]);
                        return newObj;
                    }
                    return obj;
                };
                const originalParse = JSON.parse;
                JSON.parse = function(text, reviver) {
                    const result = originalParse.call(this, text, reviver);
                    try { return pruneObject(result); } catch { return result; }
                };
            });
            this.register('trusted-prune-outbound-object', function(propPath) {
                if (!propPath) return;
                const pathParts = propPath.split('.').filter(p => p);
                const pruneObject = (obj) => {
                    if (!obj || typeof obj !== 'object') return obj;
                    const current = pathParts[0];
                    if (pathParts.length === 1) {
                        if (Array.isArray(obj)) {
                            return obj.map(item => {
                                if (item && typeof item === 'object') {const newItem = { ...item };delete newItem[current];return newItem;}
                                return item;
                            });
                        }
                        const newObj = { ...obj };
                        delete newObj[current];
                        return newObj;
                    }
                    const rest = pathParts.slice(1);
                    if (Array.isArray(obj)) {return obj.map(item => pruneObject(item));}
                    if (obj[current] && typeof obj[current] === 'object') {
                        const newObj = { ...obj };
                        newObj[current] = pruneObject(obj[current]);
                        return newObj;
                    }
                    return obj;
                };
                const originalStringify = JSON.stringify;
                JSON.stringify = function(value, replacer, space) {
                    if (typeof value === 'object' && value !== null) {
                        try {
                            const pruned = pruneObject(value);
                            return originalStringify.call(this, pruned, replacer, space);
                        } catch {}
                    }
                    return originalStringify.call(this, value, replacer, space);
                };
            });
            this.register('trusted-json-prune', function(jsonq) {
                if (!jsonq) return;
                const pathParts = jsonq.split('.').filter(p => p);
                const pruneObject = (obj) => {
                    if (!obj || typeof obj !== 'object') return obj;
                    const current = pathParts[0];
                    if (pathParts.length === 1) {
                        if (Array.isArray(obj)) {
                            return obj.map(item => {
                                if (item && typeof item === 'object') {const newItem = { ...item };delete newItem[current];return newItem;}
                                return item;
                            });
                        }
                        const newObj = { ...obj };
                        delete newObj[current];
                        return newObj;
                    }
                    const rest = pathParts.slice(1);
                    if (Array.isArray(obj)) {return obj.map(item => pruneObject(item));}
                    if (obj[current] && typeof obj[current] === 'object') {
                        const newObj = { ...obj };
                        newObj[current] = pruneObject(obj[current]);
                        return newObj;
                    }
                    return obj;
                };
                const originalParse = JSON.parse;
                JSON.parse = function(text, reviver) {
                    const result = originalParse.call(this, text, reviver);
                    try { return pruneObject(result); } catch { return result; }
                };
            });
            this.register('trusted-json-edit', function(jsonq) {this.registeredScriptlets.get('trusted-json-prune').call(this, jsonq);});
            this.register('trusted-replace-fetch-response', function(pattern, replacement, urlFilter, ...extraArgs) {
                if (!pattern) return;
                const extra = {};
                for (let i = 0; i < extraArgs.length; i += 2) {if (extraArgs[i] && extraArgs[i + 1] !== undefined) {extra[extraArgs[i]] = extraArgs[i + 1];}}
                let urlPattern = urlFilter;
                if (extra.propsToMatch) {
                    const props = extra.propsToMatch.split(',');
                    for (const prop of props) {const [key, value] = prop.split(':');if (key === 'url' && value) urlPattern = value;}
                }
                const urlTest = urlPattern ? (() => {
                    if (urlPattern.startsWith('/') && urlPattern.lastIndexOf('/') > 0) {
                        const lastSlash = urlPattern.lastIndexOf('/');
                        try {const re = new RegExp(urlPattern.slice(1, lastSlash), urlPattern.slice(lastSlash + 1));return (u) => re.test(u);} catch {}
                    }
                    if (urlPattern.includes('*')) {
                        const escaped = urlPattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*');
                        try {const re = new RegExp(escaped);return (u) => re.test(u);} catch {}
                    }
                    return (u) => u.includes(urlPattern);
                })() : () => true;
                let searchRe;
                if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
                    const lastSlash = pattern.lastIndexOf('/');
                    try {searchRe = new RegExp(pattern.slice(1, lastSlash), pattern.slice(lastSlash + 1) || 'g');} catch {}
                }
                if (!searchRe) {searchRe = new RegExp(escapeRegex(pattern), 'g');}
                // replacement argüman ayrıştırma sonrası JSON tırnaklarını içerir
                // (örn. '"no_ads"' -> '"no_ads"'); olduğu gibi kullan, geçerli JSON korunur.
                const finalReplaceValue = replacement;
                const originalFetch = window.fetch;
                window.fetch = function(input, options) {
                    const urlStr = typeof input === 'string' ? input : (input && input.url) || '';
                    if (!urlTest(urlStr)) {return originalFetch.apply(this, arguments);}
                    return originalFetch.apply(this, arguments).then(response => {
                        const clone = response.clone();
                        return clone.text().then(text => {
                            const newText = text.replace(searchRe, finalReplaceValue);
                            if (newText === text) return response;
                            return new Response(newText, {status: response.status,statusText: response.statusText,headers: response.headers});
                        }).catch(() => response);
                    });
                };
            });
            this.register('trusted-replace-xhr-response', function(pattern, replacement, urlFilter, ...extraArgs) {
                if (!pattern) return;
                const extra = {};
                for (let i = 0; i < extraArgs.length; i += 2) {if (extraArgs[i] && extraArgs[i + 1] !== undefined) {extra[extraArgs[i]] = extraArgs[i + 1];}}
                let urlPattern = urlFilter;
                if (extra.propsToMatch) {
                    const props = extra.propsToMatch.split(',');
                    for (const prop of props) {const [key, value] = prop.split(':');if (key === 'url' && value) urlPattern = value;}
                }
                const urlTest = urlPattern ? (() => {
                    if (urlPattern.startsWith('/') && urlPattern.lastIndexOf('/') > 0) {
                        const lastSlash = urlPattern.lastIndexOf('/');
                        try {const re = new RegExp(urlPattern.slice(1, lastSlash), urlPattern.slice(lastSlash + 1));return (u) => re.test(u);} catch {}
                    }
                    return (u) => u.includes(urlPattern);
                })() : () => true;
                let searchRe;
                if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
                    const lastSlash = pattern.lastIndexOf('/');
                    try {searchRe = new RegExp(pattern.slice(1, lastSlash), pattern.slice(lastSlash + 1) || 'g');} catch {}
                }
                if (!searchRe) {searchRe = new RegExp(escapeRegex(pattern), 'g');}
                // Bkz. fetch sürümü: replacement JSON tırnaklarıyla aynen kullanılır.
                const finalReplaceValue = replacement;
                const OriginalXHR = window.XMLHttpRequest;
                function PatchedXHR() {
                    const xhr = new OriginalXHR();
                    let _url = '';
                    const origOpen = xhr.open.bind(xhr);
                    const origSend = xhr.send.bind(xhr);
                    xhr.open = function(method, url, ...rest) {_url = typeof url === 'string' ? url : String(url);return origOpen(method, url, ...rest);};
                    xhr.send = function(...args) {
                        if (!urlTest(_url)) return origSend(...args);
                        xhr.addEventListener('readystatechange', function() {
                            if (this.readyState !== 4) return;
                            const ct = this.getResponseHeader('content-type') || '';
                            if (!ct.includes('json')) return;
                            try {
                                const text = this.responseText;
                                if (!text || text.length < 10) return;
                                const newText = text.replace(searchRe, finalReplaceValue);
                                if (newText !== text) {
                                    Object.defineProperty(this, 'response', {value: newText,configurable: true,writable: true});
                                    Object.defineProperty(this, 'responseText', {value: newText,configurable: true,writable: true});
                                }
                            } catch {}
                        });
                        return origSend(...args);
                    };
                    return xhr;
                }
                PatchedXHR.prototype = OriginalXHR.prototype;
                window.XMLHttpRequest = PatchedXHR;
            });
            this.register('trusted-set-attr', function(selector, attr, value) {
                if (!selector || !attr) return;
                const v = value || '';
                const apply = () => document.querySelectorAll(selector).forEach(el => el.setAttribute(attr, v));
                apply();
                watchDOM(apply);
            });
            this.register('trusted-override-element-method', function(methodPath, selector, disposition) {
                if (!methodPath) return;
                const parts = methodPath.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const methodName = parts[parts.length - 1];
                if (typeof target[methodName] !== 'function') return;
                const originalMethod = target[methodName];
                target[methodName] = function(...args) {
                    let override = selector === '';
                    if (!override && this && this.closest) {try { override = this.closest(selector) === this; } catch {}}
                    if (override) {
                        if (disposition === 'throw') throw new ReferenceError();
                        if (disposition === 'debug') debugger;
                        return;
                    }
                    return originalMethod.apply(this, args);
                };
            });
            this.register('trusted-prevent-dom-bypass', function(methodPath, targetProp) {
                if (!methodPath) return;
                const parts = methodPath.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const methodName = parts[parts.length - 1];
                if (typeof target[methodName] !== 'function') return;
                const originalMethod = target[methodName];
                const needle = targetProp ? String(targetProp) : '';
                const isPropChain = needle.includes('.');
                target[methodName] = function(...args) {
                    // Stack-filtre (uBO semantiği): çağrı yığını iğneyi içeriyorsa engelle.
                    // Örn. Node.prototype.appendChild + fetch/Request/JSON.parse.
                    if (needle && !isPropChain) {
                        let stack = '';
                        try { stack = new Error().stack || ''; } catch {}
                        let hit = false;
                        if (needle.length > 2 && needle[0] === '/' && needle.lastIndexOf('/') > 0) {
                            try { hit = new RegExp(needle.slice(1, needle.lastIndexOf('/')), needle.slice(needle.lastIndexOf('/') + 1)).test(stack); } catch { hit = stack.includes(needle); }
                        } else {
                            hit = stack.includes(needle);
                        }
                        if (hit) return undefined;
                    }
                    const result = originalMethod.apply(this, args);
                    const elems = args.filter(a => a instanceof HTMLElement);
                    for (const elem of elems) {
                        try {
                            if (elem.contentWindow && elem.contentWindow.location) {
                                if (targetProp) {
                                    let me = window, it = elem.contentWindow;
                                    const chain = targetProp.split('.');
                                    for (let i = 0; i < chain.length - 1; i++) {me = me[chain[i]];it = it[chain[i]];}
                                    it[chain[chain.length - 1]] = me[chain[chain.length - 1]];
                                } else {Object.defineProperty(elem, 'contentWindow', { value: window });}
                            }
                        } catch {}
                    }
                    return result;
                };
            });
            this.register('trusted-edit-inbound-object', function(propChain, argPos, jsonq) {
                if (!propChain || !jsonq) return;
                const pathParts = jsonq.split('.').filter(p => p);
                const editObject = (obj) => {
                    if (!obj || typeof obj !== 'object') return obj;
                    const current = pathParts[0];
                    if (pathParts.length === 1) {
                        if (Array.isArray(obj)) {
                            return obj.map(item => {
                                if (item && typeof item === 'object') {const newItem = { ...item };newItem[current] = undefined;return newItem;}
                                return item;
                            });
                        }
                        const newObj = { ...obj };
                        newObj[current] = undefined;
                        return newObj;
                    }
                    const rest = pathParts.slice(1);
                    if (Array.isArray(obj)) {return obj.map(item => editObject(item));}
                    if (obj[current] && typeof obj[current] === 'object') {
                        const newObj = { ...obj };
                        newObj[current] = editObject(obj[current]);
                        return newObj;
                    }
                    return obj;
                };
                const parts = propChain.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const fnName = parts[parts.length - 1];
                if (typeof target[fnName] !== 'function') return;
                const originalFn = target[fnName];
                const index = parseInt(argPos) || 0;
                target[fnName] = function(...args) {
                    if (args.length > index && typeof args[index] === 'object' && args[index] !== null) {
                        try { args[index] = editObject(args[index]); } catch {}
                    }
                    return originalFn.apply(this, args);
                };
            });
            this.register('trusted-edit-outbound-object', function(propChain, jsonq) {
                if (!propChain || !jsonq) return;
                const pathParts = jsonq.split('.').filter(p => p);
                const editObject = (obj) => {
                    if (!obj || typeof obj !== 'object') return obj;
                    const current = pathParts[0];
                    if (pathParts.length === 1) {
                        if (Array.isArray(obj)) {
                            return obj.map(item => {
                                if (item && typeof item === 'object') {const newItem = { ...item };newItem[current] = undefined;return newItem;}
                                return item;
                            });
                        }
                        const newObj = { ...obj };
                        newObj[current] = undefined;
                        return newObj;
                    }
                    const rest = pathParts.slice(1);
                    if (Array.isArray(obj)) {return obj.map(item => editObject(item));}
                    if (obj[current] && typeof obj[current] === 'object') {
                        const newObj = { ...obj };
                        newObj[current] = editObject(obj[current]);
                        return newObj;
                    }
                    return obj;
                };
                const parts = propChain.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const fnName = parts[parts.length - 1];
                if (typeof target[fnName] !== 'function') return;
                const originalFn = target[fnName];
                target[fnName] = function(...args) {
                    const result = originalFn.apply(this, args);
                    if (typeof result === 'object' && result !== null) {
                        try { return editObject(result); } catch {}
                    }
                    return result;
                };
            });
            this.register('trusted-replace-outbound-text', function(propChain, pattern, replacement, ...extraArgs) {
                if (!propChain || !pattern) return;
                const extra = {};
                for (let i = 0; i < extraArgs.length; i += 2) {if (extraArgs[i] && extraArgs[i + 1] !== undefined) {extra[extraArgs[i]] = extraArgs[i + 1];}}
                let searchRe;
                if (pattern.startsWith('/') && pattern.lastIndexOf('/') > 0) {
                    const lastSlash = pattern.lastIndexOf('/');
                    try {searchRe = new RegExp(pattern.slice(1, lastSlash), pattern.slice(lastSlash + 1) || 'g');} catch {}
                }
                if (!searchRe) {searchRe = new RegExp(escapeRegex(pattern), 'g');}
                const parts = propChain.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const fnName = parts[parts.length - 1];
                if (typeof target[fnName] !== 'function') return;
                const originalFn = target[fnName];
                target[fnName] = function(...args) {
                    const result = originalFn.apply(this, args);
                    if (typeof result === 'string') {
                        let text = result;
                        if (extra.encoding === 'base64') {try { text = atob(text); } catch {}}
                        if (extra.condition) {try {if (!new RegExp(extra.condition).test(text)) return result;} catch {}}
                        const newText = text.replace(searchRe, replacement || '');
                        if (newText !== text) {
                            let encoded = newText;
                            if (extra.encoding === 'base64') {try { encoded = btoa(newText); } catch {}}
                            return encoded;
                        }
                    }
                    return result;
                };
            });
            this.register('trusted-json-edit-xhr-request', function(jsonPath, editValue, ...extraArgs) {
                if (!jsonPath) return;
                const extra = {};
                for (let i = 0; i < extraArgs.length; i += 2) {if (extraArgs[i] && extraArgs[i + 1] !== undefined) {extra[extraArgs[i]] = extraArgs[i + 1];}}
                const urlPattern = extra.propsToMatch || null;
                let urlTest = () => true;
                if (urlPattern) {
                    const cleanPattern = urlPattern.replace(/^\/|\/$/g, '');
                    if (cleanPattern.startsWith('/') && cleanPattern.lastIndexOf('/') > 0) {
                        const lastSlash = cleanPattern.lastIndexOf('/');
                        try {const re = new RegExp(cleanPattern.slice(1, lastSlash), cleanPattern.slice(lastSlash + 1));urlTest = (u) => re.test(u);} catch {}
                    } else if (cleanPattern.includes('*')) {
                        const escaped = cleanPattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\*/g, '.*');
                        try {const re = new RegExp(escaped);urlTest = (u) => re.test(u);} catch {}
                    } else {urlTest = (u) => u.includes(cleanPattern);}
                }
                const parseJsonPath = (path) => {
                    const segments = [];
                    let current = '';
                    let i = 0;
                    while (i < path.length) {
                        const ch = path[i];
                        if (ch === '.' && segments.length === 0 && current === '') {i++;continue;}
                        if (ch === '[') {
                            if (current.trim()) {segments.push({ type: 'prop', name: current.trim() });current = '';}
                            let depth = 1;
                            let j = i + 1;
                            let bracketContent = '';
                            while (j < path.length && depth > 0) {
                                if (path[j] === '[') depth++;
                                else if (path[j] === ']') depth--;
                                if (depth > 0) bracketContent += path[j];
                                j++;
                            }
                            if (bracketContent.startsWith('?')) {
                                const condMatch = bracketContent.match(/^\?\.([\w.]+)\s*([*!=]=?)\s*["']?([^"']+)["']?$/);
                                if (condMatch) {segments.push({type: 'condition',prop: condMatch[1],op: condMatch[2],value: condMatch[3]});}
                            }
                            i = j;
                        } else if (ch === '+') {
                            const rest = path.slice(i + 1).trim();
                            const eqMatch = rest.match(/^=\s*(.+)$/);
                            if (eqMatch) {segments.push({ type: 'edit', value: eqMatch[1].trim() });break;}
                            i++;
                        } else if (ch === '.') {
                            if (current.trim()) {segments.push({ type: 'prop', name: current.trim() });current = '';}
                            i++;
                        } else {current += ch;i++;}
                    }
                    if (current.trim()) {segments.push({ type: 'prop', name: current.trim() });}
                    return segments;
                };
                const segments = parseJsonPath(jsonPath);
                const matchAndEdit = (obj) => {
                    if (!obj || typeof obj !== 'object') return obj;
                    let current = obj;
                    let parent = null;
                    let parentKey = null;
                    let editSegment = null;
                    for (let i = 0; i < segments.length; i++) {
                        const seg = segments[i];
                        if (seg.type === 'edit') {editSegment = seg;break;}
                        if (seg.type === 'condition') {
                            const val = current[seg.prop];
                            let matches = false;
                            if (seg.op === '*=') matches = String(val).includes(seg.value);
                            else if (seg.op === '=' || seg.op === '==') matches = String(val) === seg.value;
                            else if (seg.op === '!=') matches = String(val) !== seg.value;
                            if (!matches) return obj;
                            continue;
                        }
                        if (seg.type === 'prop') {
                            if (!(seg.name in current)) return obj;
                            parent = current;
                            parentKey = seg.name;
                            current = current[seg.name];
                        }
                    }
                    if (editSegment && parent !== null) {
                        try {
                            const editVal = JSON.parse(editSegment.value);
                            if (typeof editVal === 'object' && editVal !== null) {Object.assign(current, editVal);}
                            else {parent[parentKey] = editVal;}
                        } catch {
                            let val = editSegment.value;
                            val = val.replace(/^["']|["']$/g, '');
                            if (val === 'undefined') val = undefined;
                            else if (val === 'null') val = null;
                            else if (val === 'true') val = true;
                            else if (val === 'false') val = false;
                            else if (val === '${now}') val = Date.now();
                            parent[parentKey] = val;
                        }
                    }
                    return obj;
                };
                const OriginalXHR = window.XMLHttpRequest;
                function PatchedXHR() {
                    const xhr = new OriginalXHR();
                    let _url = '';
                    const origOpen = xhr.open.bind(xhr);
                    const origSend = xhr.send.bind(xhr);
                    xhr.open = function(method, url, ...rest) {_url = typeof url === 'string' ? url : String(url);return origOpen(method, url, ...rest);};
                    xhr.send = function(...args) {
                        if (!urlTest(_url)) return origSend(...args);
                        const reqBody = args[0];
                        if (reqBody && typeof reqBody === 'string') {
                            try {
                                const parsed = JSON.parse(reqBody);
                                const edited = matchAndEdit(parsed);
                                args[0] = JSON.stringify(edited);
                            } catch {}
                        }
                        xhr.addEventListener('readystatechange', function() {
                            if (this.readyState !== 4) return;
                            const ct = this.getResponseHeader('content-type') || '';
                            if (!ct.includes('json')) return;
                            try {
                                const text = this.responseText;
                                if (!text || text.length < 10) return;
                                const data = JSON.parse(text);
                                const edited = matchAndEdit(data);
                                const newText = JSON.stringify(edited);
                                if (newText !== text) {
                                    Object.defineProperty(this, 'response', {value: newText,configurable: true,writable: true});
                                    Object.defineProperty(this, 'responseText', {value: newText,configurable: true,writable: true});
                                }
                            } catch {}
                        });
                        return origSend(...args);
                    };
                    return xhr;
                }
                PatchedXHR.prototype = OriginalXHR.prototype;
                window.XMLHttpRequest = PatchedXHR;
            });
        }
        registerAdvancedScriptlets() {
            this.register('advanced-set-constant', function(prop, value, ...extra) {this.registeredScriptlets.get('set-constant').call(this, prop, value);});
            this.register('advanced-json-prune', function(paths, needle) {this.registeredScriptlets.get('json-prune').call(this, paths, needle);});
            this.register('advanced-json-edit', function(paths, value) {
                if (!paths) return;
                const pathParts = paths.split('.').filter(p => p);
                const editObject = (obj) => {
                    if (!obj || typeof obj !== 'object') return obj;
                    const current = pathParts[0];
                    if (pathParts.length === 1) {
                        if (Array.isArray(obj)) {
                            return obj.map(item => {
                                if (item && typeof item === 'object') {const newItem = { ...item };newItem[current] = value;return newItem;}
                                return item;
                            });
                        }
                        const newObj = { ...obj };
                        newObj[current] = value;
                        return newObj;
                    }
                    const rest = pathParts.slice(1);
                    if (Array.isArray(obj)) {return obj.map(item => editObject(item));}
                    if (obj[current] && typeof obj[current] === 'object') {
                        const newObj = { ...obj };
                        newObj[current] = editObject(obj[current]);
                        return newObj;
                    }
                    return obj;
                };
                const originalParse = JSON.parse;
                JSON.parse = function(text, reviver) {
                    const result = originalParse.call(this, text, reviver);
                    try { return editObject(result); } catch { return result; }
                };
            });
            this.register('advanced-replace-fetch', function(pattern, replacement, urlFilter) {this.registeredScriptlets.get('trusted-replace-fetch-response').call(this, pattern, replacement, urlFilter);});
            this.register('advanced-replace-xhr', function(pattern, replacement, urlFilter) {this.registeredScriptlets.get('trusted-replace-xhr-response').call(this, pattern, replacement, urlFilter);});
            this.register('advanced-prevent-fetch', function(pattern) {this.registeredScriptlets.get('prevent-fetch').call(this, pattern);});
            this.register('advanced-prevent-xhr', function(pattern) {this.registeredScriptlets.get('prevent-xhr').call(this, pattern);});
            this.register('advanced-abort-on-property', function(prop, mode) {
                if (mode === 'read') {this.registeredScriptlets.get('abort-on-property-read').call(this, prop);}
                else if (mode === 'write') {this.registeredScriptlets.get('abort-on-property-write').call(this, prop);}
            });
            this.register('advanced-override-method', function(methodPath, newFn) {
                if (!methodPath) return;
                const parts = methodPath.split('.');
                let target = window;
                for (let i = 0; i < parts.length - 1; i++) {
                    if (target[parts[i]] === undefined) return;
                    target = target[parts[i]];
                }
                const methodName = parts[parts.length - 1];
                if (typeof target[methodName] !== 'function') return;
                try {
                    const fn = new Function('return (' + newFn + ')')();
                    target[methodName] = fn;
                } catch {}
            });
            this.register('advanced-spoof-css', function(selector, prop, value) {this.registeredScriptlets.get('spoof-css').call(this, selector, prop, value);});
            this.register('advanced-block-element', function(selector) {this.registeredScriptlets.get('prevent-element').call(this, selector);});
            this.register('advanced-hide-element', function(selector) {this.registeredScriptlets.get('hide').call(this, selector);});
        }
        execute(name, args) {const key = name + '|' + JSON.stringify(args || []);if (this.injectedScriptlets.has(key)) return true;const scriptlet = this.registeredScriptlets.get(name);if (!scriptlet) {return false;}
        try {scriptlet.apply(this, args);this.injectedScriptlets.add(key);return true;}catch (e) {return false;}}
        isRegistered(name) {return this.registeredScriptlets.has(name);}
    }
    function escapeRegex(s) {return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');}
    let mainInitialized = false;
    function initMain() {
        if (mainInitialized) return;
        mainInitialized = true;
        const engine = new MainScriptletEngine();
        window.AdSecurity = window.AdSecurity || {};
        window.AdSecurity.MainScriptletEngine = engine;
        window.addEventListener('message', function(event) {
            if (event.source !== window) return;
            if (event.data && event.data.type === 'adsecurity-isolated-to-main') {
            const payload = event.data.payload;
         if (payload.action === 'executeScriptlet') {const result = engine.execute(payload.name, payload.args || []);
         window.postMessage({type: 'adsecurity-main-to-isolated',payload: {action: 'scriptletResult',name: payload.name,result: result}}, '*');}
            }
        });
    }
initMain();
})();