// Runs the real public/app.js (with the real crypto.js) on a small fake DOM, so tests drive the
// dashboard's own functions instead of matching its source text
const fs = require('fs');
const path = require('path');

const read = f => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');

function fakeElement(tagName = 'div') {
    const classes = new Set();
    const el = {
        tagName, id: '', textContent: '', innerHTML: '', value: '', checked: false, disabled: false,
        title: '', href: '', download: '', className: '', style: {}, dataset: {}, children: [], listeners: {}, sub: {},
        classList: {
            add: (...c) => c.forEach(x => classes.add(x)),
            remove: (...c) => c.forEach(x => classes.delete(x)),
            toggle: (c, force) => ((force ?? !classes.has(c)) ? classes.add(c) : classes.delete(c), classes.has(c)),
            contains: c => classes.has(c)
        },
        addEventListener(type, fn) { (el.listeners[type] ||= []).push(fn); },
        appendChild(child) { el.children.push(child); return child; },
        append(...c) { el.children.push(...c); },
        replaceChildren(...c) { el.children = c; },
        querySelector(sel) { return (el.sub[sel] ||= fakeElement()); },
        querySelectorAll() { return []; },
        setAttribute() {}, removeAttribute() {}, focus() {}, remove() {},
        click() { el.clicked = (el.clicked || 0) + 1; }
    };
    return el;
}

// fetch(url, options) answers the page's requests; storage stands in for localStorage
function loadAppPage({ fetch, confirm = () => true, storage = new Map(), hidden = [] } = {}) {
    const elements = {};
    const document = {
        getElementById: id => (elements[id] ||= Object.assign(fakeElement(), { id })),
        createElement: fakeElement,
        querySelectorAll: () => [],
        addEventListener() {},
        body: fakeElement('body')
    };
    // Elements that start hidden in index.html
    for (const id of hidden) document.getElementById(id).classList.add('hidden');
    const localStorage = {
        getItem: k => (storage.has(k) ? storage.get(k) : null),
        setItem: (k, v) => storage.set(k, String(v)),
        removeItem: k => storage.delete(k)
    };
    const window = {
        crypto: globalThis.crypto, btoa, atob, location: { origin: 'https://box.test', hash: '', search: '' },
        addEventListener() {}, localStorage
    };
    const saved = [];
    const URL_ = { createObjectURL: blob => { saved.push(blob); return `blob:${saved.length}`; }, revokeObjectURL() {} };
    const alerts = [];
    const code = `${read('crypto.js')}\n${read('app.js')}\nreturn {
        openPackage, downloadFile, handleLogin,
        get user() { return currentUser; }, set user(v) { currentUser = v; },
        set packages(v) { currentPackages = v; }
    };`;
    const page = new Function('window', 'document', 'fetch', 'localStorage', 'confirm', 'alert', 'URL', 'navigator', code)(
        window, document, fetch, localStorage, confirm, msg => alerts.push(msg), URL_, { clipboard: { writeText: async () => {} } });
    return { page, el: document.getElementById, saved, alerts, storage };
}

module.exports = { loadAppPage };
