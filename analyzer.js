/**
 * Password Strength Analyzer
 * All analysis runs locally — no data leaves the browser.
 */

// ── Constants ──────────────────────────────────────────────────

const COMMON_PASSWORDS = [
  'password','123456','qwerty','letmein','admin','welcome','monkey',
  'dragon','master','password1','abc123','iloveyou','sunshine','princess',
  'football','shadow','superman','michael','batman','trustno1',
];

const WORD_LIST = [
  'apple','brave','cloud','dance','eagle','flame','green','happy','island',
  'jungle','knight','lemon','music','noble','ocean','piano','queen','river',
  'storm','tiger','ultra','vivid','water','xenon','yacht','zebra','amber',
  'blaze','crisp','drift','ember','frost','grace','honey','ivory','jewel',
];

const CHECKS = [
  { id: 'len8',     label: 'At least 8 characters',      test: p => p.length >= 8 },
  { id: 'len12',    label: '12+ characters',              test: p => p.length >= 12 },
  { id: 'upper',    label: 'Uppercase letter (A–Z)',      test: p => /[A-Z]/.test(p) },
  { id: 'lower',    label: 'Lowercase letter (a–z)',      test: p => /[a-z]/.test(p) },
  { id: 'digit',    label: 'Number (0–9)',                test: p => /[0-9]/.test(p) },
  { id: 'symbol',   label: 'Symbol (!@#…)',               test: p => /[^a-zA-Z0-9]/.test(p) },
  { id: 'noSeq',    label: 'No sequential chars',         test: p => !/(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh)/i.test(p) },
  { id: 'noRepeat', label: 'No repeated chars (aaa)',     test: p => !/(.)\1{2,}/.test(p) },
];

// ── State ───────────────────────────────────────────────────────

const history = [];

// ── Core analysis ───────────────────────────────────────────────

/**
 * Calculate Shannon entropy based on character pool size.
 * @param {string} password
 * @returns {number} entropy in bits
 */
function calcEntropy(password) {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 32;
  return pool > 0 ? +(password.length * Math.log2(pool)).toFixed(1) : 0;
}

/**
 * Estimate crack time assuming 10 billion guesses/second (offline attack).
 * @param {number} entropyBits
 * @returns {string} human-readable time
 */
function estimateCrackTime(entropyBits) {
  const avgGuesses = Math.pow(2, entropyBits) / 2;
  const seconds    = avgGuesses / 1e10;
  if (seconds < 1)          return 'Instant';
  if (seconds < 60)         return `${Math.round(seconds)} seconds`;
  if (seconds < 3600)       return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400)      return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 31536000)   return `${Math.round(seconds / 86400)} days`;
  if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} years`;
  return `${Math.round(seconds / 3153600000)} centuries`;
}

/**
 * Score a password 1–4.
 * 1 = Weak, 2 = Fair, 3 = Strong, 4 = Very strong
 * @param {string} password
 * @returns {number}
 */
function scorePassword(password) {
  if (!password) return 0;
  if (COMMON_PASSWORDS.includes(password.toLowerCase())) return 1;
  const entropy = calcEntropy(password);
  const passed  = CHECKS.filter(c => c.test(password)).length;
  if (entropy < 28 || passed < 3) return 1;
  if (entropy < 40 || passed < 5) return 2;
  if (entropy < 60 || passed < 7) return 3;
  return 4;
}

const LEVELS = [
  null,
  { label: 'Weak',        color: '#E24B4A', badgeClass: 'badge-weak',    pct: 25  },
  { label: 'Fair',        color: '#EF9F27', badgeClass: 'badge-fair',    pct: 50  },
  { label: 'Strong',      color: '#639922', badgeClass: 'badge-strong',  pct: 75  },
  { label: 'Very strong', color: '#378ADD', badgeClass: 'badge-vstrong', pct: 100 },
];

// ── Main analyze function ────────────────────────────────────────

function analyze() {
  const pw = document.getElementById('pwInput').value;

  if (!pw) {
    resetUI();
    return;
  }

  const entropy = calcEntropy(pw);
  const score   = scorePassword(pw);
  const level   = LEVELS[score];

  // Meter
  const fill = document.getElementById('meterFill');
  fill.style.width      = level.pct + '%';
  fill.style.background = level.color;

  // Labels
  const scoreLabel = document.getElementById('scoreLabel');
  scoreLabel.textContent = level.label;
  scoreLabel.style.color = level.color;
  document.getElementById('entropyLabel').textContent = `${entropy} bits entropy`;

  // Stats row
  const crackTime = estimateCrackTime(entropy);
  const isCommon  = COMMON_PASSWORDS.includes(pw.toLowerCase());
  document.getElementById('statRow').innerHTML = `
    <div class="stat-pill"><strong>${pw.length}</strong>Length</div>
    <div class="stat-pill"><strong>${entropy}</strong>Entropy (bits)</div>
    <div class="stat-pill"><strong>${crackTime}</strong>Est. crack time</div>
    <div class="stat-pill"><strong>${isCommon ? '⚠ Yes' : '✓ No'}</strong>Common password</div>
  `;

  // Checks grid
  document.getElementById('checksGrid').innerHTML = CHECKS.map(c => {
    const ok = c.test(pw);
    return `<div class="check-item ${ok ? 'pass' : 'fail'}">
      <i class="ti ${ok ? 'ti-circle-check' : 'ti-circle-x'}" aria-hidden="true"></i>
      ${c.label}
    </div>`;
  }).join('');

  // Reuse check
  const isReuse = history.some(h => h.hash === simpleHash(pw));
  document.getElementById('reuseWarn').classList.toggle('show', isReuse);

  // Suggestions
  buildSuggestions(pw, score);
}

// ── Suggestions ──────────────────────────────────────────────────

function buildSuggestions(pw, score) {
  const area = document.getElementById('suggestArea');

  if (score >= 4) {
    area.innerHTML = `<p class="success-msg">
      <i class="ti ti-shield-check" aria-hidden="true"></i>
      Great password! No changes needed.
    </p>`;
    return;
  }

  const tips = [];
  if (pw.length < 12)                    tips.push('Make it longer — aim for at least 12 characters.');
  if (!/[A-Z]/.test(pw))                 tips.push('Add at least one uppercase letter (A–Z).');
  if (!/[0-9]/.test(pw))                 tips.push('Include one or two digits.');
  if (!/[^a-zA-Z0-9]/.test(pw))         tips.push('Add a symbol like @, #, $, or !.');
  if (/(.)\1{2,}/.test(pw))             tips.push('Avoid repeating the same character multiple times in a row.');
  if (/(012|123|234|abc|bcd)/i.test(pw)) tips.push('Remove sequential patterns like "123" or "abc".');
  if (COMMON_PASSWORDS.includes(pw.toLowerCase())) tips.push('This is one of the most common passwords — change it entirely.');
  if (calcEntropy(pw) < 50)             tips.push('Increase entropy — mix more character types or increase length.');

  area.innerHTML = tips.length
    ? tips.map(t => `
        <div class="suggestion-card">
          <i class="ti ti-bulb" aria-hidden="true"></i>
          <span>${t}</span>
        </div>`).join('')
    : `<p class="muted-text">Almost there — a little more variety will push it to "Very strong".</p>`;
}

// ── Password Generator ───────────────────────────────────────────

function generatePassword() {
  const len      = parseInt(document.getElementById('genLen').value, 10);
  const useUpper = document.getElementById('genUpper').checked;
  const useDigit = document.getElementById('genDigit').checked;
  const useSymbol= document.getElementById('genSymbol').checked;
  const useWord  = document.getElementById('genWord').checked;

  const passwords = [];

  if (useWord) {
    const symbols = ['!','@','#','$','%','&','*'];
    for (let i = 0; i < 3; i++) {
      const pick = () => WORD_LIST[Math.floor(Math.random() * WORD_LIST.length)];
      const num  = useDigit  ? `-${Math.floor(Math.random() * 900 + 100)}` : '';
      const sym  = useSymbol ? symbols[Math.floor(Math.random() * symbols.length)] : '';
      passwords.push(`${pick()}-${pick()}-${pick()}${num}${sym}`);
    }
  } else {
    let chars = 'abcdefghijklmnopqrstuvwxyz';
    if (useUpper)  chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (useDigit)  chars += '0123456789';
    if (useSymbol) chars += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    for (let i = 0; i < 3; i++) {
      let pw = '';
      for (let j = 0; j < len; j++) {
        pw += chars[Math.floor(Math.random() * chars.length)];
      }
      passwords.push(pw);
    }
  }

  document.getElementById('genResults').innerHTML = passwords.map(pw => `
    <div class="pass-row">
      <span>${pw}</span>
      <button class="copy-btn" onclick="copyToClipboard(this, ${JSON.stringify(pw)})">
        <i class="ti ti-copy" aria-hidden="true"></i> Copy
      </button>
    </div>`).join('');
}

// ── Clipboard ────────────────────────────────────────────────────

function copyToClipboard(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    btn.innerHTML = '<i class="ti ti-check"></i> Copied';
    setTimeout(() => { btn.innerHTML = '<i class="ti ti-copy"></i> Copy'; }, 1600);
  }).catch(() => {
    alert('Copy failed — please copy manually.');
  });
}

// ── History ───────────────────────────────────────────────────────

/**
 * Simple non-cryptographic hash for session reuse detection only.
 * Never use this for security purposes.
 * @param {string} str
 * @returns {string}
 */
function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
  }
  return h.toString(36);
}

function logToHistory() {
  const pw = document.getElementById('pwInput').value;
  if (!pw || pw.length < 4) return;

  const hash = simpleHash(pw);
  if (history.some(h => h.hash === hash)) return; // already logged

  const score = scorePassword(pw);
  const level = LEVELS[score];
  const masked = pw[0] + '•'.repeat(Math.max(pw.length - 2, 1)) + pw[pw.length - 1];

  history.unshift({ masked, badgeClass: level.badgeClass, label: level.label, hash });
  if (history.length > 15) history.pop();
}

function renderHistory() {
  const ul = document.getElementById('historyList');
  if (!history.length) {
    ul.innerHTML = '<li class="empty-msg">No passwords analyzed yet.</li>';
    return;
  }
  ul.innerHTML = history.map(h => `
    <li class="history-item">
      <span>${h.masked}</span>
      <span class="badge ${h.badgeClass}">${h.label}</span>
    </li>`).join('');
}

function clearHistory() {
  history.length = 0;
  renderHistory();
}

// ── Tabs ──────────────────────────────────────────────────────────

function switchTab(name) {
  const names = ['suggest', 'generate', 'history'];
  document.querySelectorAll('.tab').forEach((tab, i) => {
    const isActive = names[i] === name;
    tab.classList.toggle('active', isActive);
    tab.setAttribute('aria-selected', isActive);
  });
  document.querySelectorAll('.tab-panel').forEach(panel => panel.classList.remove('active'));
  document.getElementById(`tab-${name}`).classList.add('active');
  if (name === 'history') renderHistory();
}

// ── Eye toggle ────────────────────────────────────────────────────

function toggleEye() {
  const input = document.getElementById('pwInput');
  const icon  = document.getElementById('eyeIcon');
  if (input.type === 'password') {
    input.type      = 'text';
    icon.className  = 'ti ti-eye-off';
  } else {
    input.type      = 'password';
    icon.className  = 'ti ti-eye';
  }
}

// ── UI reset ──────────────────────────────────────────────────────

function resetUI() {
  document.getElementById('meterFill').style.width      = '0%';
  document.getElementById('meterFill').style.background = '#ccc';
  document.getElementById('scoreLabel').textContent     = '—';
  document.getElementById('scoreLabel').style.color     = '';
  document.getElementById('entropyLabel').textContent   = '';
  document.getElementById('statRow').innerHTML          = '';
  document.getElementById('checksGrid').innerHTML       = '';
  document.getElementById('suggestArea').innerHTML      = '';
  document.getElementById('reuseWarn').classList.remove('show');
}

// ── Event listeners ───────────────────────────────────────────────

document.getElementById('pwInput').addEventListener('input', analyze);
document.getElementById('pwInput').addEventListener('blur',  logToHistory);
