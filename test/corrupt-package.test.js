// A package that cannot be decrypted (garbage sent through a drop link) must still be destroyable
// from the inbox; before, openPackage only alerted and the Destroy button lives in the modal.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const openPackage = app.slice(app.indexOf('async function openPackage('), app.indexOf('function closeModal('));
const failurePath = openPackage.slice(openPackage.lastIndexOf('} catch ('));

test('a package that fails to decrypt still opens the modal with Destroy available', () => {
    assert.match(failurePath, /modal\.classList\.remove\('hidden'\)/);
    assert.match(failurePath, /btnDownloadAll\.style\.display = 'none'/);
    assert.doesNotMatch(failurePath, /btnDestroy\.(disabled = true|style\.display = 'none')/);
    assert.doesNotMatch(failurePath, /selectedPackage = null/);
});

test('the failure state says what happened, as text', () => {
    assert.match(failurePath, /getElementById\('modal-message'\)\.textContent\s*=/);
    assert.doesNotMatch(failurePath, /innerHTML\s*=\s*`[^`]*\$\{/);
});

test('the success path shows the download button again', () => {
    const success = openPackage.slice(0, openPackage.lastIndexOf('} catch ('));
    assert.match(success, /btnDownloadAll\.style\.display = 'block'/);
});
