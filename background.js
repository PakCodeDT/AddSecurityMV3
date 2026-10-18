'use strict';
/**
 * MV3 service worker girişi (klasik script — "type": "module" YOK).
 *
 * Yükleme sırası önemlidir:
 *   lib/hosts.js       hosts -> adblock normalleştirme (AdSecHosts)
 *   lib/rule-to-dnr.js FilterRule -> DNR runtime çevirici (AdSecDnr)
 *   core.js            kural motoru + DnrManager (DNR dinamik kurallar)
 *   corest.js          liste yönetimi + bootAdSecurity() (AdSecBoot)
 *
 * Ağ engelleme MV3'te declarativeNetRequest ile yapılır; webRequest
 * blocking dinleyicisi YOKTUR (core.js setup() artık kaydetmez).
 * Klasördeki @adguard/dnr-converter Node tarafında statik kurallar için
 * kullanılır: `node tools/build-dnr.mjs --input liste.txt --output dnr-rules/x.json`
 */
try {
    importScripts('lib/hosts.js', 'lib/rule-to-dnr.js', 'core.js', 'corest.js');
} catch (e) {
    console.error('[AdSecurity] background yükleme hatası:', e);
}

(function () {
    const ext = (typeof browser !== 'undefined' && browser) ||
        (typeof chrome !== 'undefined' && chrome) || {};

    function ensureBoot(reason) {
        try {
            if (typeof AdSecBoot === 'function') {
                const p = AdSecBoot();
                if (p && typeof p.catch === 'function') p.catch((e) => {
                    console.warn('[AdSecurity] boot (' + reason + '):', (e && e.message) || e);
                });
                return p;
            }
        } catch (e) {
            console.warn('[AdSecurity] boot (' + reason + '):', (e && e.message) || e);
        }
        return null;
    }

    // SW her uyanışta: importScripts zaten çalıştı, corest.js boot'u tetikledi.
    // Kurulum/güncelleme ve tarayıcı açılışında yeniden garantiye al.
    try {
        if (ext.runtime && ext.runtime.onInstalled) {
            ext.runtime.onInstalled.addListener(() => { ensureBoot('installed'); });
        }
        if (ext.runtime && ext.runtime.onStartup) {
            ext.runtime.onStartup.addListener(() => { ensureBoot('startup'); });
        }
    } catch (e) { /* API yoksa sessiz geç */ }
})();
