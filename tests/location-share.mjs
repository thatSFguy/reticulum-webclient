import assert from 'node:assert/strict';
import test from 'node:test';
import { locationDetails, createLocationMessage, requestLocation, locationErrorMessage } from '../js/location-share.js';

// Synthetic test coordinates only. No device location is requested by tests.
const position = {
  coords: { latitude: 48.462071, longitude: 9.947084, accuracy: 7.4 },
  timestamp: Date.UTC(2026, 10, 1, 12, 0, 0),
};

test('message contains coordinates, rounded-up accuracy, timestamp and an HTTPS map link', () => {
  const text = createLocationMessage(position);
  assert.equal(text, 'My location: 48.462071, 9.947084\nAccuracy: ±8 m\nRecorded: 2026-11-01T12:00:00.000Z\nhttps://www.openstreetmap.org/?mlat=48.462071&mlon=9.947084#map=16/48.462071/9.947084');
});

test('map link can be omitted without dropping location information', () => {
  const text = createLocationMessage(position, { includeMapLink: false });
  assert.match(text, /My location: 48\.462071, 9\.947084/);
  assert.match(text, /Accuracy: ±8 m/);
  assert.match(text, /Recorded:/);
  assert.doesNotMatch(text, /https?:/);
});

test('negative and boundary coordinates are valid; accuracy is never understated', () => {
  const result = locationDetails({ coords: { latitude: -90, longitude: 180, accuracy: 1000.1 }, timestamp: 0 });
  assert.equal(result.coordinates, '-90.000000, 180.000000');
  assert.equal(result.accuracy, '±1001 m');
  assert.equal(result.timestamp, '1970-01-01T00:00:00.000Z');
});

for (const [field, value] of [['latitude', 91], ['latitude', NaN], ['longitude', -181],
  ['longitude', '9'], ['accuracy', -1], ['accuracy', Infinity]]) {
  test(`invalid ${field} is rejected (${String(value)})`, () => {
    assert.throws(() => createLocationMessage({ ...position, coords: { ...position.coords, [field]: value } }), /invalid location/);
  });
}
test('missing coordinates and invalid timestamps are rejected', () => {
  assert.throws(() => locationDetails(null), /invalid location/);
  assert.throws(() => locationDetails({ ...position, timestamp: 1e20 }), /invalid location/);
  assert.throws(() => locationDetails({ ...position, timestamp: undefined }), /invalid location/);
});

test('only one fresh position is requested; continuous tracking is not used', async () => {
  let calls = 0;
  const result = await requestLocation({
    getCurrentPosition(success, error, options) {
      calls++;
      assert.deepEqual(options, { enableHighAccuracy: true, maximumAge: 0, timeout: 15000 });
      success(position);
    },
    watchPosition() { assert.fail('Continuous tracking must not be requested'); },
  });
  assert.equal(calls, 1);
  assert.equal(result, position);
});

test('permission and unavailable-browser failures propagate without retrying', async () => {
  let calls = 0;
  await assert.rejects(requestLocation({ getCurrentPosition(success, error) { calls++; error({ code: 1 }); } }), error => error.code === 1);
  assert.equal(calls, 1);
  await assert.rejects(requestLocation({}), /not supported/);
  await assert.rejects(requestLocation({ getCurrentPosition() { throw new Error('device error'); } }), /device error/);
});

test('permission denial, unavailable position and timeout have useful explanations', () => {
  assert.match(locationErrorMessage({ code: 1 }), /permission was denied/);
  assert.match(locationErrorMessage({ code: 2 }), /unavailable/);
  assert.match(locationErrorMessage({ code: 3 }), /timed out/);
  assert.match(locationErrorMessage(null), /Could not get/);
});
