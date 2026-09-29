/* Argon2 Virtual Lab JS - genuine in-browser Argon2 via hash-wasm. */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }

  function bytesToHex(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }

  function hexToBytes(hex) {
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) return null;
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function bytesToB64u(b) {
    var bin = '';
    for (var i = 0; i < b.length; i++) bin += String.fromCharCode(b[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64uToBytes(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/]/g, '');
    while (s.length % 4 !== 0) s += '=';
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function fmtKiB(kib) {
    return kib >= 1024 ? (kib / 1024).toFixed(0) + ' MiB' : kib + ' KiB';
  }

  function fmtMs(ms) {
    return ms >= 1000 ? (ms / 1000).toFixed(2) + ' s' : ms.toFixed(1) + ' ms';
  }

  function setNote(el, ok, text) {
    el.className = ok ? 'callout info' : 'callout warn';
    el.style.display = '';
    el.textContent = text;
  }

  function newSaltHex() {
    var b = new Uint8Array(16);
    crypto.getRandomValues(b);
    return bytesToHex(b);
  }

  function phcParse(s) {
    var p = s.trim().split('$');
    if (p.length !== 6 || !/^argon2(id|i|d)$/.test(p[1]) || p[2] !== 'v=19') return null;
    var kv = {};
    p[3].split(',').forEach(function (x) { var a = x.split('='); kv[a[0]] = parseInt(a[1], 10); });
    if (!kv.m || !kv.t || !kv.p) return null;
    var salt, tag;
    try { salt = b64uToBytes(p[4]); tag = b64uToBytes(p[5]); } catch (e) { return null; }
    return { variant: p[1], m: kv.m, t: kv.t, p: kv.p, salt: salt, tag: tag };
  }

  function fnFor(variant) {
    if (typeof hashwasm === 'undefined') {
      throw new Error('hash-wasm library not loaded (no internet?). Reconnect and reload the page.');
    }
    return hashwasm[variant];
  }

  function friendlyError(e) {
    var s = String(e && e.message || e);
    if (/not loaded|internet/i.test(s)) return s;
    if (/memory|allocat/i.test(s)) return 'The browser refused to allocate that much memory. Try a smaller memory cost (m).';
    if (/too small/i.test(s)) return 'Memory cost too small: RFC 9106 requires m >= 8*p KiB. Lower p or raise m.';
    return 'Hashing failed: ' + s;
  }

  function hashOnce(variant, password, salt, m, t, p, tagLen, outputType) {
    return fnFor(variant)({
      password: new TextEncoder().encode(password),
      salt: salt,
      iterations: t,
      parallelism: p,
      memorySize: m,
      hashLength: tagLen,
      outputType: outputType
    });
  }

  /* PBKDF2-SHA256 via the browser's built-in WebCrypto (256-bit key) */
  function pbkdf2Once(password, salt, iterations) {
    var key;
    return crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
      .then(function (k) { key = k; })
      .then(function () {
        return crypto.subtle.deriveBits(
          { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations }, key, 256);
      });
  }

  /* ---------- generic tab switcher ---------- */
  function initTabs() {
    var bar = $('tabbar');
    if (!bar) return;
    bar.addEventListener('click', function (ev) {
      var btn = ev.target.closest('button');
      if (!btn) return;
      bar.querySelectorAll('button').forEach(function (b) { b.classList.toggle('on', b === btn); });
      document.querySelectorAll('.tabpane').forEach(function (p) { p.classList.remove('on'); });
      var pane = $('pane-' + btn.getAttribute('data-tab'));
      if (pane) pane.classList.add('on');
    });
  }

  /* ---------- Hasher tab ---------- */
  function initHasher() {
    var pw = $('h-password'), saltIn = $('h-salt'), mS = $('h-m'), tS = $('h-t'), pS = $('h-p');
    if (!pw) return;
    saltIn.value = newSaltHex();

    function syncLabels() {
      var m = parseInt(mS.value, 10);
      $('h-m-val').textContent = m + ' KiB' + (m >= 1024 ? '  (~' + (m / 1024).toFixed(0) + ' MiB)' : '');
      $('h-t-val').textContent = tS.value;
      $('h-p-val').textContent = pS.value;
    }
    [mS, tS, pS].forEach(function (s) { s.addEventListener('input', syncLabels); });
    syncLabels();

    $('h-new-salt').addEventListener('click', function () { saltIn.value = newSaltHex(); });

    $('h-compute').addEventListener('click', function () {
      var err = $('h-error'), res = $('h-result');
      res.style.display = 'none';
      err.style.display = 'none';
      var saltBytes = hexToBytes(saltIn.value.trim());
      if (!saltBytes || saltBytes.length < 8) {
        setNote(err, false, 'Salt must be even-length hex, at least 8 bytes (16 bytes recommended).');
        return;
      }
      var variant = $('h-variant').value, m = parseInt(mS.value, 10),
          t = parseInt(tS.value, 10), p = parseInt(pS.value, 10), tagLen = parseInt($('h-tag').value, 10) || 32;
      var btn = $('h-compute');
      btn.disabled = true;
      var t0 = performance.now();
      hashOnce(variant, pw.value, saltBytes, m, t, p, tagLen, 'encoded').then(function (phc) {
        var dt = performance.now() - t0;
        $('h-time').textContent = fmtMs(dt);
        $('h-mem').textContent = fmtKiB(m);
        $('h-variant-out').textContent = variant;
        $('h-phc').textContent = phc;
        return hashOnce(variant, pw.value, saltBytes, m, t, p, tagLen, 'binary');
      }).then(function (tag) {
        $('h-tag-hex').textContent = bytesToHex(tag);
        res.style.display = '';
      }).catch(function (e) {
        setNote(err, false, friendlyError(e));
      }).finally(function () { btn.disabled = false; });
    });

    $('h-to-verify').addEventListener('click', function () {
      $('v-phc').value = $('h-phc').textContent;
      $('v-password').value = pw.value;
      $('tabbar').querySelector('[data-tab="verify"]').click();
    });
  }

  /* ---------- Verify tab ---------- */
  function initVerify() {
    var box = $('v-phc');
    if (!box) return;
    $('v-check').addEventListener('click', function () {
      var res = $('v-result'), err = $('v-error');
      res.style.display = 'none';
      err.style.display = 'none';
      var parsed = phcParse(box.value);
      if (!parsed) {
        setNote(err, false, 'Could not parse that PHC string. Expected: $argon2id$v=19$m=..,t=..,p=..$salt$tag');
        return;
      }
      var btn = $('v-check');
      btn.disabled = true;
      var t0 = performance.now();
      hashOnce(parsed.variant, $('v-password').value, parsed.salt, parsed.m, parsed.t, parsed.p,
        parsed.tag.length, 'binary').then(function (tag) {
        var dt = performance.now() - t0;
        var match = tag.length === parsed.tag.length &&
          tag.every(function (b, i) { return b === parsed.tag[i]; });
        setNote(res, match, (match ? 'MATCH - password correct. ' : 'NO MATCH - wrong password. ') +
          'Re-derivation took ' + fmtMs(dt) + ' with the stored work factor (m=' + parsed.m +
          ', t=' + parsed.t + ', p=' + parsed.p + ') - same cost as hashing, so no timing oracle.');
      }).catch(function (e) {
        setNote(err, false, friendlyError(e));
      }).finally(function () { btn.disabled = false; });
    });
  }

  /* ---------- Memory Grid animation ---------- */
  function initMemoryGrid() {
    var grid = $('mg-grid');
    if (!grid) return;
    var TOTAL = 64, token = 0;

    for (var i = 0; i < TOTAL; i++) {
      var c = document.createElement('div');
      c.className = 'mem-cell';
      grid.appendChild(c);
    }
    var cells = grid.children;

    function reset() {
      for (var i = 0; i < TOTAL; i++) {
        cells[i].className = 'mem-cell';
        cells[i].title = 'block ' + i;
      }
    }

    function run() {
      var my = ++token;
      reset();
      var variant = $('mg-variant').value, t = parseInt($('mg-t').value, 10);
      var written = 0;
      function step(i, pass) {
        if (my !== token) return;
        for (var k = 0; k < TOTAL; k++) cells[k].classList.remove('cur', 'ref');
        var idMode = variant === 'argon2i' || (variant === 'argon2id' && pass === 1 && i < TOTAL / 2);
        var j1 = -1;
        if (i > 0) {
          if (idMode) {
            j1 = Math.floor((Math.abs(Math.sin(i * 12.9898 + pass * 78.233) * 43758.5453) % 1) * written);
          } else {
            j1 = Math.floor(written * 0.15 + (Math.abs(Math.sin(i * 4.898 + pass * 3.21) * 23321.77) % 1) * written * 0.85);
            if (j1 > written - 1) j1 = written - 1;
          }
        }
        if (j1 >= 0) cells[j1].classList.add('ref');
        cells[i].classList.add('cur');
        cells[i].classList.add(pass >= 3 ? 'pass2' : (pass === 2 ? 'pass1' : 'pass0'));
        written = i + 1;
        $('mg-note').textContent = 'pass ' + pass + ' - writing block ' + i +
          ' from reference block(s) ' + (j1 >= 0 ? j1 : 'H0 (initial hash)') +
          (idMode ? '  [data-independent]' : '  [data-dependent]');
        setTimeout(function () {
          if (my !== token) return;
          if (i + 1 < TOTAL) { step(i + 1, pass); }
          else if (pass < t) { step(0, pass + 1); }
          else { $('mg-note').textContent = 'Fill complete: ' + (t * TOTAL) + ' block-writes. Final tag = BLAKE2b of XOR of lane tails (simplified here to one lane).'; }
        }, 45);
      }
      step(0, 1);
    }

    $('mg-run').addEventListener('click', run);
  }

  /* ---------- shared benchmark runner ---------- */
  function runBench(runBtn, tbody, errEl, configs) {
    runBtn.disabled = true;
    errEl.style.display = 'none';
    tbody.innerHTML = '';
    var chain = Promise.resolve();
    configs.forEach(function (cfg) {
      chain = chain.then(function () {
        var t0 = performance.now();
        return cfg.fn().then(function () { return performance.now() - t0; });
      }).then(function (dt) {
        var row = tbody.insertRow();
        row.insertCell().textContent = cfg.name;
        row.insertCell().textContent = fmtMs(dt);
        row.insertCell().textContent = dt > 0 ? (1000 / dt).toFixed(1) : '-';
        row.insertCell().textContent = cfg.mem;
      }).then(function () { return new Promise(function (r) { setTimeout(r, 0); }); });
    });
    chain.catch(function (e) { setNote(errEl, false, friendlyError(e)); })
      .finally(function () { runBtn.disabled = false; });
  }

  function initBenchmark() {
    if (!$('b-run')) return;
    $('b-run').addEventListener('click', function () {
      var m = parseInt($('b-m').value, 10), t = parseInt($('b-t').value, 10),
          p = parseInt($('b-p').value, 10), iters = parseInt($('b-iters').value, 10);
      var configs = [
        { name: 'Argon2id (m=' + m + ', t=' + t + ', p=' + p + ')', mem: fmtKiB(m),
          fn: function () { return hashOnce('argon2id', 'benchmark password', crypto.getRandomValues(new Uint8Array(16)), m, t, p, 32, 'binary'); } },
        { name: 'PBKDF2-SHA-256 (' + iters.toLocaleString() + ' iter)', mem: '-',
          fn: function () { return pbkdf2Once('benchmark password', new Uint8Array(16), iters); } }
      ];
      runBench($('b-run'), $('b-results'), $('b-error'), configs);
    });
  }

  /* ---------- demos page ---------- */
  function initDemos() {
    var d1run = $('d1-run');
    if (d1run) {
      d1run.addEventListener('click', function () {
        var pw = $('d1-password').value || 'hunter2';
        var users = ['alice', 'bob', 'carol'];
        var errEl = $('d1-error');
        errEl.style.display = 'none';
        d1run.disabled = true;
        var chain = Promise.resolve();
        var rowsU = [], rowsS = [];
        users.forEach(function (u) {
          var ss = crypto.getRandomValues(new Uint8Array(16));
          chain = chain
            .then(function () {
              return hashOnce('argon2id', pw, new Uint8Array(16), 8, 1, 1, 32, 'binary');
            })
            .then(function (tu) {
              rowsU.push([u, '00000000...', bytesToHex(tu).slice(0, 16) + '...']);
              return hashOnce('argon2id', pw, ss, 8, 1, 1, 32, 'binary');
            })
            .then(function (ts) {
              rowsS.push([u, bytesToHex(ss).slice(0, 8) + '...', bytesToHex(ts).slice(0, 16) + '...']);
            });
        });
        chain.then(function () {
          var spec = [
            ['d1-table-u', rowsU, 'd1-verdict-u', true],
            ['d1-table-s', rowsS, 'd1-verdict-s', false]
          ];
          spec.forEach(function (s) {
            var tb = $(s[0]);
            tb.innerHTML = '';
            var sameAll = s[1][0][2] === s[1][1][2] && s[1][1][2] === s[1][2][2];
            s[1].forEach(function (r, idx) {
              var row = tb.insertRow();
              row.insertCell().textContent = r[0];
              row.insertCell().textContent = r[1];
              row.insertCell().textContent = r[2];
              row.insertCell().textContent = idx === 0 ? '-' : (r[2] === s[1][0][2] ? 'IDENTICAL' : 'different');
            });
            setNote($(s[2]), !sameAll, sameAll
              ? 'All three hashes are IDENTICAL - one cracked hash owns all 3 accounts. A single rainbow-table row covers every user.'
              : 'Hashes differ despite the same password - precomputed tables are useless; the attacker must attack each user separately (3x the work).');
          });
        }).catch(function (e) { setNote(errEl, false, friendlyError(e)); })
          .finally(function () { d1run.disabled = false; });
      });
    }

    var d2run = $('d2-run');
    if (d2run) {
      d2run.addEventListener('click', function () {
        var pw = $('d2-password').value || 'correct horse battery staple';
        var presets = [
          { n: 'a', m: 8, t: 1, p: 1 },
          { n: 'b', m: 262144, t: 1, p: 1 },
          { n: 'c', m: 19456, t: 2, p: 1 },
          { n: 'd', m: 19456, t: 2, p: 4 }
        ];
        var tb = $('d2-results'), errEl = $('d2-error');
        errEl.style.display = 'none';
        tb.innerHTML = '';
        d2run.disabled = true;
        var chain = Promise.resolve();
        presets.forEach(function (pr) {
          chain = chain
            .then(function () {
              var t0 = performance.now();
              return hashOnce('argon2id', pw, crypto.getRandomValues(new Uint8Array(16)), pr.m, pr.t, pr.p, 32, 'binary')
                .then(function () { return performance.now() - t0; });
            })
            .then(function (dt) {
              var row = tb.insertRow();
              row.insertCell().textContent = '(' + pr.n + ')';
              row.insertCell().textContent = pr.m;
              row.insertCell().textContent = pr.t;
              row.insertCell().textContent = pr.p;
              row.insertCell().textContent = fmtKiB(pr.m);
              row.insertCell().textContent = fmtMs(dt);
            })
            .then(function () { return new Promise(function (r) { setTimeout(r, 0); }); });
        });
        chain.catch(function (e) { setNote(errEl, false, friendlyError(e)); })
          .finally(function () { d2run.disabled = false; });
      });
    }

    var d3run = $('d3-run');
    if (d3run) {
      d3run.addEventListener('click', function () {
        runBench(d3run, $('d3-results'), $('d3-error'), [
          { name: 'Argon2id weak (8 KiB, t=1, p=1)', mem: '8 KiB',
            fn: function () { return hashOnce('argon2id', 'benchmark password', crypto.getRandomValues(new Uint8Array(16)), 8, 1, 1, 32, 'binary'); } },
          { name: 'Argon2id interactive (19 MiB, t=2, p=1)', mem: '~19 MiB',
            fn: function () { return hashOnce('argon2id', 'benchmark password', crypto.getRandomValues(new Uint8Array(16)), 19456, 2, 1, 32, 'binary'); } },
          { name: 'Argon2id sensitive (64 MiB, t=3, p=1)', mem: '~64 MiB',
            fn: function () { return hashOnce('argon2id', 'benchmark password', crypto.getRandomValues(new Uint8Array(16)), 65536, 3, 1, 32, 'binary'); } },
          { name: 'PBKDF2-SHA-256 (600,000 iter)', mem: '-',
            fn: function () { return pbkdf2Once('benchmark password', new Uint8Array(16), 600000); } }
        ]);
      });
    }
  }

  /* ---------- assignment page: reveal toggles ---------- */
  function initAssignment() {
    document.querySelectorAll('.reveal').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var box = btn.closest('.panel').querySelector('.reveal-box');
        if (box) {
          var open = box.style.display !== 'none';
          box.style.display = open ? 'none' : '';
          btn.textContent = open ? 'Show key points' : 'Hide key points';
        }
      });
    });
  }

  /* ---------- feedback page ---------- */
  function initFeedback() {
    var btn = $('fb-submit');
    if (!btn) return;
    btn.addEventListener('click', function () {
      var sel = function (id) { var e = $(id); return e ? e.value : ''; };
      var thanks = $('fb-thanks');
      thanks.innerHTML = '';
      var line1 = document.createElement('b');
      line1.textContent = 'Thank you! Your feedback has been recorded locally:';
      thanks.appendChild(line1);
      var ul = document.createElement('ul');
      [['Theory clarity', 'fb-where'], ['Simulation difficulty', 'fb-diff'],
       ['Performance', 'fb-perf']].forEach(function (pair) {
        var li = document.createElement('li');
        li.textContent = pair[0] + ': ' + sel(pair[1]);
        ul.appendChild(li);
      });
      if (sel('fb-text')) {
        var li = document.createElement('li');
        li.textContent = 'Comments: ' + sel('fb-text');
        ul.appendChild(li);
      }
      thanks.appendChild(ul);
      thanks.style.display = '';
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    initTabs();
    initHasher();
    initVerify();
    initMemoryGrid();
    initBenchmark();
    initDemos();
    initAssignment();
    initFeedback();
  });
})();
