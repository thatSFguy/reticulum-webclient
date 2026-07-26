// js/transport-flasher-app.js — UI controller for flasher.html.
// Fetches the latest release of reticulum-lora-repeater, lets the
// user download the matching UF2 (drag-and-drop install path) or
// Web-Serial-DFU-flash a locally uploaded firmware.zip, and after the
// device is running, configures it over BLE or Web Serial via the
// msgpack protocol in ../reticulum-lora-repeater/docs/CONFIG_FORMAT.md
// (transport wiring in docs/SERIAL_PROTOCOL.md).

import {
  TransportClient,
  hzToMhz, mhzToHz,
  latLonToUdeg, udegToLatLon,
} from './transport-config.js';

const TRANSPORT_OWNER = 'thatSFguy';
const TRANSPORT_REPO  = 'reticulum-lora-repeater';
const RELEASES_URL    = `https://api.github.com/repos/${TRANSPORT_OWNER}/${TRANSPORT_REPO}/releases/latest`;

// ---------------------------------------------------------------
//  DOM shortcuts
// ---------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const log = (cls, msg) => {
  const el = $('log');
  if (!el) return;
  const span = document.createElement('span');
  span.className = cls;
  span.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg + '\n';
  el.appendChild(span);
  el.scrollTop = el.scrollHeight;
};

// ---------------------------------------------------------------
//  Browser support gates
// ---------------------------------------------------------------
function checkSupport() {
  if (!('serial' in navigator) && !('bluetooth' in navigator)) {
    $('unsupported').classList.remove('hidden');
  }
  if (location.protocol !== 'https:' && location.hostname !== 'localhost' && location.hostname !== '127.0.0.1') {
    $('http-warn').classList.remove('hidden');
  }
}

// ---------------------------------------------------------------
//  Latest release fetch
// ---------------------------------------------------------------
let latestRelease = null;        // parsed GitHub release object
let selectedAsset = null;        // chosen .uf2 asset for the picked board

async function fetchLatestRelease() {
  $('rel-status').textContent = 'Loading latest release…';
  try {
    const res = await fetch(RELEASES_URL, { cache: 'no-cache' });
    if (res.status === 404) {
      throw new Error('repo is private or has no public releases (HTTP 404)');
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    latestRelease = await res.json();

    const uf2Assets = (latestRelease.assets || []).filter(a => a.name.endsWith('.uf2'));
    if (uf2Assets.length === 0) {
      throw new Error('latest release has no .uf2 assets');
    }

    const boardSel = $('rel-board');
    boardSel.innerHTML = '';
    for (const a of uf2Assets) {
      const board = parseBoard(a.name);
      const opt = document.createElement('option');
      opt.value = a.name;
      opt.textContent = board;
      boardSel.appendChild(opt);
    }
    boardSel.disabled = false;
    onBoardChange();
    $('rel-status').textContent = `Latest: ${latestRelease.tag_name} — ${uf2Assets.length} board(s) available`;
    $('rel-version-label').textContent = latestRelease.tag_name;
    log('info', `Loaded release ${latestRelease.tag_name} with ${uf2Assets.length} UF2 asset(s)`);
  } catch (e) {
    $('rel-status').textContent = 'Could not load latest release: ' + e.message;
    log('err', 'release fetch failed: ' + e.message);
    $('release-warn').classList.remove('hidden');
  }
}

// reticulum-lora-repeater-Heltec_T114-v0.6.3.uf2 → "Heltec_T114"
// (also accepts the pre-rename firmware-<board>-v*.uf2 asset naming)
function parseBoard(filename) {
  const m = filename.match(/^(?:reticulum-lora-repeater|firmware)-(.+)-v[\d.]+\.uf2$/);
  return m ? m[1] : filename;
}

function onBoardChange() {
  const boardSel = $('rel-board');
  if (!latestRelease || !boardSel.value) {
    selectedAsset = null;
    $('btn-download-uf2').disabled = true;
    return;
  }
  selectedAsset = (latestRelease.assets || []).find(a => a.name === boardSel.value);
  $('btn-download-uf2').disabled = !selectedAsset;
}

// ---------------------------------------------------------------
//  UF2 download (anchor-link path — no CORS needed)
// ---------------------------------------------------------------
function downloadUf2() {
  if (!selectedAsset) return;
  const a = document.createElement('a');
  a.href = selectedAsset.browser_download_url;
  a.download = selectedAsset.name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  log('info', 'Triggered download: ' + selectedAsset.name);
  $('uf2-instructions').classList.remove('hidden');
}

// ---------------------------------------------------------------
//  DFU flash — local .zip upload only (transport CI does not yet
//  publish .zip and CORS blocks fetch() of release-asset URLs)
// ---------------------------------------------------------------
let loadedDfuPackage = null;

async function onDfuFileChange(ev) {
  const file = ev.target.files[0];
  if (!file) return;
  $('fw-info').textContent = 'parsing ' + file.name + '…';
  try {
    loadedDfuPackage = await window.RLRDfu.DfuPackage.fromFile(file);
    $('fw-info').textContent = file.name + ' — firmware ' + loadedDfuPackage.firmware.length + ' B';
    $('btn-flash').disabled = false;
    log('ok', 'loaded DFU package: ' + file.name);
  } catch (e) {
    loadedDfuPackage = null;
    $('fw-info').textContent = 'parse failed: ' + e.message;
    log('err', 'DFU package parse failed: ' + e.message);
    $('btn-flash').disabled = true;
  }
}

async function flashDfu() {
  if (!loadedDfuPackage) return;
  if (!('serial' in navigator)) {
    log('err', 'Web Serial not supported in this browser');
    return;
  }
  const btn = $('btn-flash');
  btn.disabled = true;
  $('fw-stage').textContent = 'Pick the bootloader serial port';
  let port;
  try {
    port = await navigator.serial.requestPort();
    await port.open({ baudRate: 115200, dataBits: 8, stopBits: 1, parity: 'none' });
  } catch (e) {
    btn.disabled = false;
    log('err', 'Could not open serial port: ' + e.message);
    $('fw-stage').textContent = '';
    return;
  }
  try {
    await window.RLRDfu.dfuFlash(port, loadedDfuPackage, {
      onStage: (s) => { $('fw-stage').textContent = s; log('info', 'DFU: ' + s); },
      onProgress: (sent, total) => {
        const pct = Math.floor(100 * sent / total);
        $('fw-progress-bar').style.width = pct + '%';
      },
      log: (cls, msg) => log(cls, msg),
    });
    log('ok', 'flash complete — board is rebooting');
    $('fw-stage').textContent = 'Done. Reconnect once the board comes back up.';
  } catch (e) {
    log('err', 'flash failed: ' + e.message);
    $('fw-stage').textContent = 'failed: ' + e.message;
  } finally {
    try { await port.close(); } catch (e) {}
    btn.disabled = false;
  }
}

// ---------------------------------------------------------------
//  Configurator
// ---------------------------------------------------------------
const client = new TransportClient(log);
let currentConfig = null;

async function connectUsb() {
  try {
    await client.connectSerial();
    onConnected();
  } catch (e) {
    log('err', 'USB connect failed: ' + e.message);
  }
}

async function connectBle() {
  try {
    await client.connectBle();
    onConnected();
  } catch (e) {
    log('err', 'BLE connect failed: ' + e.message);
  }
}

async function disconnect() {
  await client.disconnect();
  onDisconnected();
}

async function onConnected() {
  setConnDot(true);
  $('btn-connect').classList.add('hidden');
  $('btn-connect-ble').classList.add('hidden');
  $('btn-disconnect').classList.remove('hidden');
  $('live').classList.remove('hidden');
  $('loading-overlay').classList.remove('hidden');
  $('config-panel').classList.add('hidden');

  client.onDisconnect = () => onDisconnected();

  try {
    const pong = await client.ping();
    log('ok', 'pong from device, version=' + pong.version);
    $('dev-identity').textContent = bytesToHex(pong.identity_hash);
    $('dev-version').textContent  = pong.version || '?';
    await refreshConfig();
  } catch (e) {
    log('err', 'initial handshake failed: ' + e.message);
    $('loading-overlay').textContent = 'Handshake failed: ' + e.message;
  }
}

function onDisconnected() {
  setConnDot(false);
  $('btn-connect').classList.remove('hidden');
  $('btn-connect-ble').classList.remove('hidden');
  $('btn-disconnect').classList.add('hidden');
  $('live').classList.add('hidden');
  currentConfig = null;
}

function setConnDot(on) {
  const dot = $('conn-dot');
  const txt = $('conn-text');
  if (on) { dot.classList.add('on'); dot.classList.remove('err'); txt.textContent = 'Connected'; }
  else    { dot.classList.remove('on'); txt.textContent = 'Disconnected'; }
}

async function refreshConfig() {
  $('loading-overlay').classList.remove('hidden');
  $('config-panel').classList.add('hidden');
  try {
    currentConfig = await client.getConfig();
    populateConfigForm(currentConfig);
    $('loading-overlay').classList.add('hidden');
    $('config-panel').classList.remove('hidden');
    log('ok', 'config loaded');
  } catch (e) {
    log('err', 'get_config failed: ' + e.message);
    $('loading-overlay').textContent = 'get_config failed: ' + e.message;
  }
}

function populateConfigForm(cfg) {
  $('cfg-display_name').value  = cfg.display_name || '';
  $('cfg-freq_mhz').value      = hzToMhz(cfg.freq_hz).toString();
  $('cfg-bw_hz').value          = String(cfg.bw_hz);
  $('cfg-sf').value             = String(cfg.sf);
  $('cfg-cr').value             = String(cfg.cr);
  $('cfg-txp_dbm').value        = String(cfg.txp_dbm);
  $('cfg-latitude').value       = cfg.lat_udeg ? udegToLatLon(cfg.lat_udeg).toFixed(6) : '';
  $('cfg-longitude').value      = cfg.lon_udeg ? udegToLatLon(cfg.lon_udeg).toFixed(6) : '';
  $('cfg-altitude').value       = cfg.alt_m || 0;
  $('cfg-batt_mult').value      = (cfg.batt_mult ?? 1).toFixed(3);
}

function readConfigForm() {
  const lat = parseFloat($('cfg-latitude').value);
  const lon = parseFloat($('cfg-longitude').value);
  return {
    display_name: $('cfg-display_name').value.slice(0, 31),
    freq_hz:      mhzToHz(parseFloat($('cfg-freq_mhz').value)),
    bw_hz:        parseInt($('cfg-bw_hz').value, 10),
    sf:           parseInt($('cfg-sf').value, 10),
    cr:           parseInt($('cfg-cr').value, 10),
    txp_dbm:      parseInt($('cfg-txp_dbm').value, 10),
    lat_udeg:     Number.isFinite(lat) ? latLonToUdeg(lat) : 0,
    lon_udeg:     Number.isFinite(lon) ? latLonToUdeg(lon) : 0,
    alt_m:        parseInt($('cfg-altitude').value, 10) || 0,
    batt_mult:    parseFloat($('cfg-batt_mult').value),
  };
}

async function applyAndCommit() {
  const fields = readConfigForm();
  try {
    const r = await client.setConfig(fields);
    log('ok', 'set_config applied ' + r.set + ' field(s)');
    await client.commit();
    log('ok', 'commit OK');
    await refreshConfig();
  } catch (e) {
    log('err', 'apply failed: ' + e.message);
  }
}

async function geolocate() {
  if (!navigator.geolocation) {
    log('err', 'geolocation API not available');
    return;
  }
  $('btn-geolocate').disabled = true;
  navigator.geolocation.getCurrentPosition(
    (pos) => {
      $('cfg-latitude').value  = pos.coords.latitude.toFixed(6);
      $('cfg-longitude').value = pos.coords.longitude.toFixed(6);
      if (pos.coords.altitude != null) $('cfg-altitude').value = Math.round(pos.coords.altitude);
      log('ok', 'geolocation filled in');
      $('btn-geolocate').disabled = false;
    },
    (err) => {
      log('err', 'geolocation: ' + err.message);
      $('btn-geolocate').disabled = false;
    },
    { enableHighAccuracy: true, timeout: 10000 },
  );
}

function bytesToHex(bytes) {
  if (!bytes) return '?';
  if (bytes instanceof Uint8Array) {
    return [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  }
  // msgpack may surface bin8 as a plain object {type,data} or ArrayBuffer
  if (bytes.byteLength != null) {
    return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
  }
  return String(bytes);
}

// ---------------------------------------------------------------
//  Boot
// ---------------------------------------------------------------
window.addEventListener('DOMContentLoaded', () => {
  checkSupport();

  $('rel-board').addEventListener('change', onBoardChange);
  $('btn-download-uf2').addEventListener('click', downloadUf2);
  $('fw-file').addEventListener('change', onDfuFileChange);
  $('btn-flash').addEventListener('click', flashDfu);

  $('btn-connect').addEventListener('click', connectUsb);
  $('btn-connect-ble').addEventListener('click', connectBle);
  $('btn-disconnect').addEventListener('click', disconnect);
  $('btn-refresh').addEventListener('click', refreshConfig);
  $('btn-commit').addEventListener('click', applyAndCommit);
  $('btn-geolocate').addEventListener('click', geolocate);

  if (!('bluetooth' in navigator)) {
    $('btn-connect-ble').disabled = true;
    $('btn-connect-ble').title = 'Web Bluetooth not available in this browser';
  }
  if (!('serial' in navigator)) {
    $('btn-connect').disabled = true;
    $('btn-connect').title = 'Web Serial not available in this browser';
  }

  fetchLatestRelease();
});
