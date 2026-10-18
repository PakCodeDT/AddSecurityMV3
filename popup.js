'use strict';

const $ = id => document.getElementById(id);

let currentHostname = '';
let currentMode = 'normal';
let currentTabId = null;

async function getSiteMode(hostname) {
  // core.js ile aynı anahtar: adsecurity_disabled_sites
  const data = await browser.storage.local.get('adsecurity_disabled_sites');
  const list = Array.isArray(data.adsecurity_disabled_sites) ? data.adsecurity_disabled_sites : [];
  return list.includes(hostname) ? 'off' : 'normal';
}

async function setSiteMode(hostname, mode) {
  const data = await browser.storage.local.get('adsecurity_disabled_sites');
  let list = Array.isArray(data.adsecurity_disabled_sites) ? data.adsecurity_disabled_sites.slice() : [];

  if (mode === 'off') {
    if (!list.includes(hostname)) list.push(hostname);
  } else {
    list = list.filter(h => h !== hostname);
  }

  await browser.storage.local.set({ adsecurity_disabled_sites: list });
  // storage.onChanged zaten core.js ve content script'lerde dinleniyor;
  // ekstra mesaj göndermeye gerek yok.
}

function renderState(hostname, mode) {
  const modeSelect = $('mode-select');
  const modeIcon = $('mode-icon');
  const statusDot = $('status-dot');
  const siteName = $('site-name');
  const siteStatus = $('site-status');

  if (!modeSelect || !modeIcon || !statusDot || !siteName || !siteStatus) return;

  siteName.textContent = hostname || 'Bilinmeyen site';
  modeSelect.value = mode;

  switch (mode) {
    case 'normal':
      modeIcon.src = browser.runtime.getURL('a.png');
      statusDot.className = 'status-dot';
      siteStatus.textContent = 'Normal Mod - Aktif';
      siteStatus.className = 'site-status';
      break;
    case 'off':
      modeIcon.src = browser.runtime.getURL('a.png');
      statusDot.className = 'status-dot off';
      siteStatus.textContent = 'Devre Dışı';
      siteStatus.className = 'site-status off';
      break;
  }
}

async function init() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return;

  let hostname = '';
  try {
    hostname = new URL(tab.url).hostname;
  } catch (e) {}

  currentHostname = hostname;
  currentTabId = tab.id;

  const manifest = browser.runtime.getManifest();
  const footerVer = $('footer-ver');
  if (footerVer) footerVer.textContent = 'v' + manifest.version;

  if (hostname) {
    currentMode = await getSiteMode(hostname);
    renderState(hostname, currentMode);
  } else {
    renderState('Geçersiz sayfa', 'off');
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    await init();
  } catch (e) {
    console.error('[Popup] init hatası:', e);
    const siteName = $('site-name');
    const siteStatus = $('site-status');
    if (siteName) siteName.textContent = 'Yüklenemedi';
    if (siteStatus) siteStatus.textContent = 'Hata oluştu';
  }

  const modeSelect = $('mode-select');
  if (modeSelect) {
    modeSelect.addEventListener('change', async () => {
      if (!currentHostname) return;
      
      const newMode = modeSelect.value;
      
      try {
        await setSiteMode(currentHostname, newMode);
        currentMode = newMode;
        renderState(currentHostname, newMode);
        
        if (currentTabId != null) {
          try {
            await browser.tabs.reload(currentTabId);
          } catch (e) {
            console.error('[Popup] Sekme yenilenemedi:', e);
          }
        }
      } catch (e) {
        console.error('[Popup] Mod değiştirme hatası:', e);
      }
    });
  }

  const btnSettings = $('btn-settings');
  if (btnSettings) {
    btnSettings.addEventListener('click', () => {
      browser.runtime.openOptionsPage();
      window.close();
    });
  }

  const btnAbout = $('btn-about');
  if (btnAbout) {
    btnAbout.addEventListener('click', () => {
      browser.tabs.create({ url: browser.runtime.getURL('about.html') });
      window.close();
    });
  }
});