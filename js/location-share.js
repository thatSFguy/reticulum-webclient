// One-shot, user-initiated location sharing. Never track or send automatically.
'use strict';

export function locationDetails(position) {
  const { latitude, longitude, accuracy } = position?.coords || {};
  const timestamp = position?.timestamp;
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90 ||
      !Number.isFinite(longitude) || longitude < -180 || longitude > 180 ||
      !Number.isFinite(accuracy) || accuracy < 0 ||
      !Number.isFinite(timestamp) || !Number.isFinite(new Date(timestamp).getTime())) {
    throw new Error('The device returned an invalid location. Please try again.');
  }
  const lat = latitude.toFixed(6);
  const lon = longitude.toFixed(6);
  return {
    coordinates: `${lat}, ${lon}`,
    accuracy: `±${Math.ceil(accuracy)} m`,
    timestamp: new Date(timestamp).toISOString(),
    mapUrl: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=16/${lat}/${lon}`,
  };
}

export function createLocationMessage(position, { includeMapLink = true } = {}) {
  const details = locationDetails(position);
  const lines = [
    `My location: ${details.coordinates}`,
    `Accuracy: ${details.accuracy}`,
    `Recorded: ${details.timestamp}`,
  ];
  if (includeMapLink) lines.push(details.mapUrl);
  return lines.join('\n');
}

export function requestLocation(geolocation = globalThis.navigator?.geolocation) {
  return new Promise((resolve, reject) => {
    if (typeof geolocation?.getCurrentPosition !== 'function') {
      reject(new Error('Location sharing is not supported by this browser.'));
      return;
    }
    geolocation.getCurrentPosition(resolve, reject, {
      enableHighAccuracy: true,
      maximumAge: 0,
      timeout: 15000,
    });
  });
}

export function locationErrorMessage(error) {
  switch (error?.code) {
    case 1: return 'Location permission was denied. Allow location access for this site in Safari or your browser settings, then try again.';
    case 2: return 'Your position is unavailable. Check Location Services and try again.';
    case 3: return 'Getting your position timed out. Try again, preferably where the device has a clear view of the sky.';
    default: return error instanceof Error ? error.message : 'Could not get your position. Please try again.';
  }
}

export function initLocationSharing({ getRecipient, getRecipientName }) {
  const button = document.getElementById('btn-location');
  const overlay = document.getElementById('location-modal');
  // A tab can briefly have cached, older HTML during a static-site update.
  if (!button || !overlay) return { cancel() {} };
  const dialog = overlay.querySelector('[role="dialog"]');
  const status = document.getElementById('location-status');
  const details = document.getElementById('location-details');
  const coordinates = document.getElementById('location-coordinates');
  const accuracy = document.getElementById('location-accuracy');
  const recorded = document.getElementById('location-recorded');
  const includeLink = document.getElementById('location-include-link');
  const retry = document.getElementById('location-retry');
  const cancelButton = document.getElementById('location-cancel');
  const add = document.getElementById('location-add');
  const draft = document.getElementById('msg-content');
  let requestId = 0;
  let recipient = null;
  let position = null;
  let previousFocus = null;

  function cancel() {
    requestId++; // getCurrentPosition cannot be aborted; ignore any late callback.
    position = null;
    recipient = null;
    overlay.classList.add('hidden');
    dialog.setAttribute('aria-busy', 'false');
    coordinates.textContent = accuracy.textContent = recorded.textContent = '';
    recorded.removeAttribute('datetime');
    previousFocus?.focus();
    previousFocus = null;
  }

  async function locate() {
    if (!recipient || recipient !== getRecipient()) { cancel(); return; }
    const currentRequest = ++requestId;
    position = null;
    add.disabled = true;
    retry.disabled = true;
    details.classList.add('hidden');
    dialog.setAttribute('aria-busy', 'true');
    status.textContent = 'Requesting your current position… You may need to allow location access.';
    try {
      if (!window.isSecureContext) throw new Error('Location sharing requires HTTPS.');
      const result = await requestLocation();
      if (currentRequest !== requestId) return;
      if (recipient !== getRecipient()) { cancel(); return; }
      const info = locationDetails(result);
      position = result;
      coordinates.textContent = info.coordinates;
      accuracy.textContent = info.accuracy;
      recorded.textContent = new Date(info.timestamp).toLocaleString();
      recorded.setAttribute('datetime', info.timestamp);
      details.classList.remove('hidden');
      status.textContent = 'Review this position. Add it to your draft, then press Send when ready. Your device may provide an approximate location.';
      add.disabled = false;
    } catch (error) {
      if (currentRequest === requestId) status.textContent = locationErrorMessage(error);
    } finally {
      if (currentRequest === requestId) {
        retry.disabled = false;
        dialog.setAttribute('aria-busy', 'false');
      }
    }
  }

  button.addEventListener('click', () => {
    if (!getRecipient()) return;
    recipient = getRecipient();
    previousFocus = document.activeElement;
    includeLink.checked = true;
    document.getElementById('location-recipient').textContent = `To: ${getRecipientName()}`;
    overlay.classList.remove('hidden');
    cancelButton.focus();
    locate();
  });
  retry.addEventListener('click', locate);
  cancelButton.addEventListener('click', cancel);
  overlay.addEventListener('click', event => { if (event.target === overlay) cancel(); });
  overlay.addEventListener('keydown', event => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); cancel(); }
    if (event.key !== 'Tab') return;
    const focusable = [...dialog.querySelectorAll('button:not(:disabled), input:not(:disabled)')]
      .filter(element => element.offsetParent !== null);
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  });
  add.addEventListener('click', () => {
    if (!position || recipient !== getRecipient()) { cancel(); return; }
    const message = createLocationMessage(position, { includeMapLink: includeLink.checked });
    draft.value += `${draft.value ? '\n\n' : ''}${message}`;
    draft.dispatchEvent(new Event('input', { bubbles: true }));
    cancel();
    draft.focus();
    draft.setSelectionRange(draft.value.length, draft.value.length);
  });
  return { cancel };
}
