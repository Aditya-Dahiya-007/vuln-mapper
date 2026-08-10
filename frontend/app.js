/* ============================================================
   Vuln-Mapper front-end
   Modes: Live Recon (DAST) and Code Audit (SAST + AI fix)
   Scans run as background jobs (start -> poll), persist to
   SQLite, and can be re-opened from history or exported to PDF.
   ============================================================ */

/* ============================================================
   Vuln-Mapper front-end
   ============================================================ */

/* API base:
   - Local dev: leave blank -> calls hit the same server (relative URLs).
   - Split deploy (frontend on Vercel, backend on Render/Railway): set this to
     your backend's public URL, e.g. "https://vuln-mapper-api.onrender.com".
   You can also set window.VULN_MAPPER_API in a <script> before app.js loads. */
const API_BASE = (window.VULN_MAPPER_API || "").replace(/\/$/, "");
const api = (path) => `${API_BASE}${path}`;

const scanBtn     = document.getElementById('scanBtn');
const statusPill  = document.getElementById('statusPill');
const statusLabel = statusPill.querySelector('.navbar__status-label');
const orb         = document.getElementById('scanOrb');
const orbCaption  = document.getElementById('orbCaption');
const resultsDiv  = document.getElementById('results');
const targetInput = document.getElementById('targetInput');

let findings = [];        // current audit findings (for remediation)
let currentScanId = null; // id of the scan shown in #results

function setState(state, label) {
  statusPill.className = 'navbar__status' + (state === 'idle' ? '' : ' is-' + state);
  statusLabel.textContent = label;
  orb.className = 'orb' + (state === 'idle' ? '' : ' is-' + state);
  orbCaption.className = 'orb-caption' + (state === 'idle' ? '' : ' is-' + state);
}

function escapeHtml(str) {
  return String(str == null ? '' : str).replace(/[&<>"']/g, c => (
    { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]
  ));
}

function infoMsg(text) {
  return `<div class="msg msg--info">${escapeHtml(text)}
    <span class="scan-loader"><span></span><span></span><span></span></span></div>`;
}

/* ============================================================
   MODE SWITCHING
   ============================================================ */
const modeSwitch  = document.querySelector('.mode-switch');
const modeButtons = document.querySelectorAll('.mode-switch__btn');
const liveConsole = document.getElementById('liveConsole');
const codeConsole = document.getElementById('codeConsole');
const eyebrow     = document.getElementById('eyebrow');
const heroLede    = document.getElementById('heroLede');

const COPY = {
  recon: {
    eyebrow: 'Recon & Vulnerability Console',
    lede: 'Drop in an IP or a hostname. We sweep the ports, fingerprint every banner, cross-reference live CVE data, and fuzz for directories no one was supposed to find.',
    caption: 'awaiting target',
  },
  audit: {
    eyebrow: 'Static Analysis & AI Remediation',
    lede: 'Upload your source. Bandit and Semgrep find the real flaws, then a local AI explains each one and writes the fix — all on your machine, no keys, no cloud.',
    caption: 'awaiting source',
  },
};

let llmChecked = false;
let llmProvider = 'ollama';   // 'ollama' (local) | 'gemini' (cloud)

function switchMode(mode) {
  const isRecon = mode === 'recon';
  modeButtons.forEach(b => b.classList.toggle('is-active', b.dataset.mode === mode));
  modeSwitch.classList.toggle('is-audit', !isRecon);
  liveConsole.hidden = !isRecon;
  codeConsole.hidden = isRecon;
  eyebrow.textContent  = COPY[mode].eyebrow;
  heroLede.textContent = COPY[mode].lede;
  resultsDiv.innerHTML = '';
  setState('idle', 'Standing by');
  orbCaption.textContent = COPY[mode].caption;
  if (!isRecon && !llmChecked) { checkLlmStatus(); llmChecked = true; }
}

modeButtons.forEach(btn => btn.addEventListener('click', () => switchMode(btn.dataset.mode)));

/* ============================================================
   JOB POLLING
   ============================================================ */
function pollJob(jobId) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = async () => {
      try {
        const r = await fetch(api(`/api/job/${jobId}`));
        if (!r.ok) throw new Error('job lookup failed');
        const scan = await r.json();
        if (scan.status === 'done') return resolve(scan);
        if (scan.status === 'error') return reject(new Error(scan.error || 'scan failed'));
        if (Date.now() - started > 300000) return reject(new Error('scan timed out'));
        setTimeout(tick, 1500);
      } catch (e) { reject(e); }
    };
    tick();
  });
}

/* ============================================================
   RESULT RENDERING (shared by fresh scans and history playback)
   ============================================================ */
function exportBar(scan) {
  const kindLabel = scan.kind === 'audit' ? 'Code audit' : 'Recon scan';
  const aiBtn = scan.kind === 'audit'
    ? `<button class="export-btn export-btn--ai" id="aiReportBtn" data-scan="${scan.id}" type="button">
         <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>
         AI report
       </button>`
    : '';
  return `<div class="result-bar">
    <div class="result-bar__label">${kindLabel} · <span class="target-value">${escapeHtml(scan.label || '')}</span></div>
    <div class="result-bar__actions">
      <a class="export-btn" href="${api(`/api/report/${scan.id}`)}" target="_blank" rel="noopener">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M12 3v12m0 0l-4-4m4 4l4-4M5 21h14" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        Export PDF
      </a>
      ${aiBtn}
    </div>
  </div>
  <div class="ai-progress" id="aiProgress" hidden></div>`;
}

function renderResult(scan) {
  currentScanId = scan.id;
  const bar = exportBar(scan);
  if (scan.kind === 'audit') {
    findings = (scan.result && scan.result.findings) || [];
    resultsDiv.innerHTML = bar + findingsHtml(scan.result);
    document.querySelectorAll('.fix-btn').forEach(btn => {
      btn.addEventListener('click', () => handleFix(parseInt(btn.dataset.index, 10), btn));
    });
    const aiBtn = document.getElementById('aiReportBtn');
    if (aiBtn) aiBtn.addEventListener('click', () => startAiReport(aiBtn.dataset.scan, aiBtn));
  } else {
    resultsDiv.innerHTML = bar + reconHtml(scan.result);
    attachTiltHandlers();
  }
  resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ---------- recon rendering ---------- */
function reconHtml(data) {
  if (!data || !data.recon || data.recon.length === 0) {
    return `<div class="msg msg--empty">No open ports discovered on ${escapeHtml((data && data.target) || 'target')}.</div>`;
  }
  let html = `<div class="section-title">Port Reconnaissance</div>`;
  data.recon.forEach(res => {
    html += `
      <div class="port-card">
        <div class="port-card__head">
          <span class="port-chip"><span class="port-chip__num">${escapeHtml(res.port)}</span>Port</span>
          <span class="banner-tag">${escapeHtml(res.service_banner)}</span>
        </div>
        <hr class="divider">
        <p class="vuln-label">Discovered Vulnerabilities</p>`;
    if (!res.vulnerabilities || res.vulnerabilities.length === 0) {
      html += "<p class='vuln-clean'>No CVEs found, or version hidden.</p>";
    } else if (res.vulnerabilities[0].error) {
      html += `<p class='vuln-warn'>${escapeHtml(res.vulnerabilities[0].error)}</p>`;
    } else {
      res.vulnerabilities.forEach(v => {
        html += `<div class="vuln-item"><span class="vuln-item__id">${escapeHtml(v.cve_id)}</span>
                 <span class="vuln-item__summary">${escapeHtml(v.summary)}</span></div>`;
      });
    }
    html += `</div>`;
  });
  if (data.directories && data.directories.length > 0) {
    html += `<div class="section-title">Hidden Directories Discovered</div><div class="dir-panel">`;
    data.directories.forEach(dir => {
      const badgeClass = dir.status === 200 ? "status-badge--ok" : "status-badge--warn";
      html += `<div class="dir-row">
          <a href="http://${escapeHtml(data.target)}${escapeHtml(dir.directory)}" target="_blank" rel="noopener">${escapeHtml(dir.directory)}</a>
          <span class="status-badge ${badgeClass}">${escapeHtml(dir.status)}</span>
        </div>`;
    });
    html += `</div>`;
  } else {
    html += `<div class="msg msg--empty">No common hidden directories found.</div>`;
  }
  return html;
}

/* ---------- audit rendering ---------- */
function sevClass(sev) {
  sev = (sev || '').toUpperCase();
  if (sev === 'HIGH') return 'high';
  if (sev === 'MEDIUM') return 'med';
  return 'low';
}
function toolFlag(name, tools) {
  const t = (tools && tools[name]) || {};
  return `<span class="tool-flag ${t.ran ? 'is-ok' : 'is-off'}"><span class="tool-flag__dot"></span>${escapeHtml(name)}</span>`;
}
function highlightContext(ctx) {
  return ctx.split('\n').map(line => {
    const flagged = /^\s*\d+\s*>>/.test(line);
    return `<span class="code-line${flagged ? ' code-line--flag' : ''}">${escapeHtml(line)}</span>`;
  }).join('');
}
function findingCard(f, i) {
  const sc = sevClass(f.severity);
  const cwe = f.cwe ? `<span class="chip chip--cwe">${escapeHtml(f.cwe)}</span>` : '';
  const code = f.context ? `<pre class="code-block">${highlightContext(f.context)}</pre>` : '';
  return `
    <div class="finding finding--${sc}" data-index="${i}">
      <div class="finding__head">
        <div class="finding__title-wrap">
          <span class="sev-badge sev-badge--${sc}">${escapeHtml(f.severity || '')}</span>
          <span class="finding__title">${escapeHtml(f.title || f.rule_id || 'finding')}</span>
        </div>
        <div class="finding__meta">
          <span class="chip chip--tool">${escapeHtml(f.tool || '')}</span>${cwe}
        </div>
      </div>
      <div class="finding__loc">${escapeHtml(f.file || '')}<span class="finding__line">:${escapeHtml(f.line)}</span></div>
      <p class="finding__msg">${escapeHtml(f.message || '')}</p>
      ${code}
      <div class="finding__actions">
        <button class="fix-btn" data-index="${i}">
          <svg class="fix-btn__spark" viewBox="0 0 24 24" fill="none"><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/></svg>
          <span class="fix-btn__label">Explain &amp; fix</span>
        </button>
      </div>
      <div class="remediation" id="rem-${i}"></div>
    </div>`;
}
function findingsHtml(data) {
  const list = (data && data.findings) || [];
  if (!list.length) {
    return `<div class="msg msg--empty">Clean scan — no issues found in ${escapeHtml((data && data.filename) || 'the archive')}.</div>`;
  }
  const s = data.summary || { total: 0, high: 0, medium: 0, low: 0 };
  let html = `
    <div class="audit-summary">
      <div class="stat stat--total"><span class="stat__num">${s.total}</span><span class="stat__label">findings</span></div>
      <div class="stat stat--high"><span class="stat__num">${s.high}</span><span class="stat__label">high</span></div>
      <div class="stat stat--med"><span class="stat__num">${s.medium}</span><span class="stat__label">medium</span></div>
      <div class="stat stat--low"><span class="stat__num">${s.low}</span><span class="stat__label">low</span></div>
      <div class="tool-flags">${toolFlag('bandit', data.tools)}${toolFlag('semgrep', data.tools)}</div>
    </div>
    <div class="section-title">Findings</div>`;
  html += list.map((f, i) => findingCard(f, i)).join('');
  return html;
}

/* ============================================================
   LIVE RECON
   ============================================================ */
scanBtn.addEventListener('click', (e) => {
  const ripple = scanBtn.querySelector('.btn__ripple');
  const rect = scanBtn.getBoundingClientRect();
  ripple.style.left = (e.clientX - rect.left) + 'px';
  ripple.style.top  = (e.clientY - rect.top) + 'px';
  ripple.classList.remove('is-active');
  void ripple.offsetWidth;
  ripple.classList.add('is-active');
});

function attachTiltHandlers() {
  document.querySelectorAll('.port-card').forEach(card => {
    card.addEventListener('mousemove', (e) => {
      const rect = card.getBoundingClientRect();
      const x = (e.clientX - rect.left) / rect.width - 0.5;
      const y = (e.clientY - rect.top) / rect.height - 0.5;
      card.style.setProperty('--ry', `${x * 8}deg`);
      card.style.setProperty('--rx', `${-y * 8}deg`);
    });
    card.addEventListener('mouseleave', () => {
      card.style.setProperty('--rx', '0deg');
      card.style.setProperty('--ry', '0deg');
    });
  });
}

async function runScan() {
  const target = targetInput.value;
  if (!target) {
    resultsDiv.innerHTML = "<div class='msg msg--error'>Enter a target IP or hostname to scan.</div>";
    return;
  }
  scanBtn.disabled = true;
  setState('scanning', 'Scanning');
  orbCaption.textContent = 'sweeping target…';
  resultsDiv.innerHTML = infoMsg('Scanning ports and fuzzing directories...');
  try {
    const r = await fetch(api(`/api/scan/start?target=${encodeURIComponent(target)}`), { method: 'POST' });
    if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.detail || r.status); }
    const { job_id } = await r.json();
    const scan = await pollJob(job_id);
    setState('done', 'Complete');
    renderResult(scan);
    loadHistory();
  } catch (e) {
    setState('error', 'Error');
    resultsDiv.innerHTML = `<div class="msg msg--error">Scan failed: ${escapeHtml(e.message || e)}. Is uvicorn running?</div>`;
  } finally {
    scanBtn.disabled = false;
  }
}
scanBtn.addEventListener('click', runScan);
targetInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); runScan(); } });

/* ============================================================
   CODE AUDIT
   ============================================================ */
const dropzone     = document.getElementById('dropzone');
const zipInput     = document.getElementById('zipInput');
const dropzoneText = document.getElementById('dropzoneText');
const analyzeBtn   = document.getElementById('analyzeBtn');
const llmChip      = document.getElementById('llmChip');

let selectedFile = null;

async function checkLlmStatus() {
  const label = llmChip.querySelector('.llm-chip__label');
  llmChip.className = 'llm-chip is-checking';
  label.textContent = 'Checking AI…';
  try {
    const s = await (await fetch(api('/api/llm-status'))).json();
    llmProvider = s.provider || 'ollama';
    const isCloud = llmProvider === 'gemini';
    if (s.ok && s.model_present) {
      llmChip.className = 'llm-chip is-ready'; label.textContent = `AI ready · ${s.configured_model}`;
    } else if (s.ok && !s.model_present) {
      llmChip.className = 'llm-chip is-warn'; label.textContent = `Pull model: ${s.configured_model}`;
    } else {
      llmChip.className = 'llm-chip is-off';
      label.textContent = isCloud ? 'AI offline · check API key' : 'AI offline · start Ollama';
    }
  } catch (e) {
    llmChip.className = 'llm-chip is-off'; label.textContent = 'AI status unknown';
  }
}

function setFile(f) {
  if (!f) return;
  if (!f.name.toLowerCase().endsWith('.zip')) {
    dropzoneText.innerHTML = 'That isn\'t a <b>.zip</b> — pick a zipped source archive';
    dropzone.classList.remove('has-file'); analyzeBtn.disabled = true; selectedFile = null; return;
  }
  selectedFile = f;
  dropzoneText.textContent = f.name;
  dropzone.classList.add('has-file');
  analyzeBtn.disabled = false;
}

dropzone.addEventListener('click', () => zipInput.click());
dropzone.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); zipInput.click(); } });
zipInput.addEventListener('change', () => setFile(zipInput.files[0]));
dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('is-drag'); });
dropzone.addEventListener('dragleave', (e) => { e.preventDefault(); dropzone.classList.remove('is-drag'); });
dropzone.addEventListener('drop', (e) => { e.preventDefault(); dropzone.classList.remove('is-drag'); setFile(e.dataTransfer.files[0]); });

async function runAnalyze() {
  if (!selectedFile) return;
  analyzeBtn.disabled = true;
  setState('scanning', 'Analyzing');
  orbCaption.textContent = 'auditing code…';
  resultsDiv.innerHTML = infoMsg(`Running Bandit + Semgrep on ${selectedFile.name}...`);
  try {
    const fd = new FormData();
    fd.append('file', selectedFile);
    const r = await fetch(api('/api/analyze/start'), { method: 'POST', body: fd });
    if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.detail || r.status); }
    const { job_id } = await r.json();
    const scan = await pollJob(job_id);
    setState('done', 'Complete');
    renderResult(scan);
    loadHistory();
  } catch (e) {
    setState('error', 'Error');
    resultsDiv.innerHTML = `<div class="msg msg--error">Analysis failed: ${escapeHtml(e.message || e)}</div>`;
  } finally {
    analyzeBtn.disabled = false;
  }
}
analyzeBtn.addEventListener('click', runAnalyze);

/* ============================================================
   AI REMEDIATION (on demand, per finding) — unchanged flow
   ============================================================ */
async function handleFix(i, btn) {
  const panel = document.getElementById('rem-' + i);
  const label = btn.querySelector('.fix-btn__label');
  const state = panel.dataset.state || 'empty';
  if (state === 'loading') return;
  if (state === 'loaded') {
    const open = panel.classList.toggle('is-open');
    label.textContent = open ? 'Hide fix' : 'Explain & fix';
    return;
  }
  panel.dataset.state = 'loading';
  btn.classList.add('is-loading');
  label.textContent = 'Analyzing…';
  panel.classList.add('is-open');
  panel.innerHTML = `<div class="rem-loading">${llmProvider === 'gemini'
      ? 'Asking Gemini to analyse this finding — usually a few seconds.'
      : 'Consulting the local model — the first call loads it into memory and can take 15–60s.'}
    <span class="scan-loader"><span></span><span></span><span></span></span></div>`;
  try {
    const r = await fetch(api('/api/remediate'), {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(findings[i]),
    });
    const data = await r.json();
    if (!data.ok) throw new Error(data.error || 'remediation failed');
    renderRemediation(data, panel);
    panel.dataset.state = 'loaded';
    label.textContent = 'Hide fix';
  } catch (e) {
    panel.dataset.state = 'empty';
    panel.innerHTML = `<div class="rem-error">Couldn't generate a fix: ${escapeHtml(e.message || e)}
      <span class="rem-error__hint">${llmProvider === 'gemini'
        ? 'Check your GEMINI_API_KEY and rate limits, then try again.'
        : 'Make sure Ollama is running and the model is pulled, then try again.'}</span></div>`;
    label.textContent = 'Explain & fix';
  } finally {
    btn.classList.remove('is-loading');
  }
}

function renderRemediation(data, panel) {
  panel.innerHTML = `
    <div class="rem">
      <div class="rem__model">Generated locally by ${escapeHtml(data.model || 'model')}</div>
      <div class="rem__block rem__block--cause"><div class="rem__label">Root cause</div><p class="rem__text">${escapeHtml(data.root_cause)}</p></div>
      <div class="rem__block rem__block--attack"><div class="rem__label">How it's exploited</div><p class="rem__text">${escapeHtml(data.attack_mechanics)}</p></div>
      <div class="rem__block rem__block--fix"><div class="rem__label">Secure fix</div>
        <div class="rem__code-wrap"><button class="copy-btn" type="button">Copy</button><pre class="rem__code">${escapeHtml(data.secure_code)}</pre></div>
      </div>
    </div>`;
  const copyBtn = panel.querySelector('.copy-btn');
  copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(data.secure_code || '').then(() => {
      copyBtn.textContent = 'Copied'; setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
    });
  });
}

/* ============================================================
   AI-REMEDIATED REPORT (loops the model over every finding)
   ============================================================ */
function aiProgressHtml(done, total) {
  const pct = (typeof total === 'number' && total) ? Math.round(done / total * 100) : 0;
  return `<div class="ai-progress__bar"><span style="width:${pct}%"></span></div>
    <div class="ai-progress__label">Generating fixes… ${done} of ${total}${llmProvider === 'gemini'
      ? ' — sent one at a time to stay inside the free-tier rate limit.'
      : ' — each runs locally, so this takes a while.'}</div>`;
}

function pollAiReport(jobId, prog) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const tick = async () => {
      try {
        const scan = await (await fetch(api(`/api/job/${jobId}`))).json();
        if (scan.status === 'done') return resolve(scan);
        if (scan.status === 'error') return reject(new Error(scan.error || 'report failed'));
        const p = scan.summary || {};
        prog.innerHTML = aiProgressHtml(p.done || 0, (p.total != null ? p.total : '?'));
        if (Date.now() - started > 1800000) return reject(new Error('report timed out'));
        setTimeout(tick, 1500);
      } catch (e) { reject(e); }
    };
    tick();
  });
}

async function startAiReport(scanId, btn) {
  const prog = document.getElementById('aiProgress');
  btn.disabled = true;
  prog.hidden = false;
  prog.innerHTML = `<div class="ai-progress__label">${llmProvider === 'gemini'
    ? 'Starting — sending findings to Gemini…'
    : 'Starting — loading the local model…'}</div>`;
  try {
    const r = await fetch(api(`/api/report/ai/${scanId}/start`), { method: 'POST' });
    if (!r.ok) { const j = await r.json().catch(() => ({})); throw new Error(j.detail || r.status); }
    const { job_id, total } = await r.json();
    prog.innerHTML = aiProgressHtml(0, total);
    const done = await pollAiReport(job_id, prog);
    prog.innerHTML = `<div class="ai-progress__label ai-progress__label--ok">Report ready — downloading…</div>`;
    window.location.href = api(`/api/report/${done.id}`);
    setTimeout(() => { prog.hidden = true; }, 4000);
  } catch (e) {
    prog.innerHTML = `<div class="ai-progress__label ai-progress__label--err">Report failed: ${escapeHtml(e.message || e)}</div>`;
  } finally {
    btn.disabled = false;
  }
}

/* ============================================================
   HISTORY
   ============================================================ */
const historyList    = document.getElementById('historyList');
const historyRefresh = document.getElementById('historyRefresh');

function summaryText(s) {
  if (!s.summary) return '';
  if (s.kind === 'audit') {
    const x = s.summary; return `${x.total || 0} findings${x.high ? ` · ${x.high} high` : ''}`;
  }
  const x = s.summary; return `${x.ports || 0} ports · ${x.directories || 0} dirs`;
}

function historyRow(s) {
  const time = (s.created_at || '').replace('T', ' ');
  const statusCls = s.status === 'done' ? 'ok' : (s.status === 'error' ? 'err' : 'run');
  const canOpen = s.status === 'done';
  const sub = summaryText(s);
  return `
    <div class="history-row">
      <span class="history-kind history-kind--${s.kind}">${s.kind === 'audit' ? 'CODE' : 'RECON'}</span>
      <div class="history-main">
        <div class="history-label">${escapeHtml(s.label || '')}</div>
        <div class="history-sub">${escapeHtml(time)}${sub ? ' · ' + escapeHtml(sub) : ''}</div>
      </div>
      <span class="history-status history-status--${statusCls}">${escapeHtml(s.status)}</span>
      <div class="history-actions">
        ${canOpen ? `<button class="ghost-btn" data-open="${s.id}">Open</button>` : ''}
        ${canOpen ? `<a class="ghost-btn" href="${api(`/api/report/${s.id}`)}" target="_blank" rel="noopener">PDF</a>` : ''}
        <button class="ghost-btn ghost-btn--x" data-del="${s.id}" title="Delete">×</button>
      </div>
    </div>`;
}

async function loadHistory() {
  try {
    const { scans } = await (await fetch(api('/api/history?limit=15'))).json();
    if (!scans || !scans.length) {
      historyList.innerHTML = `<div class="history-empty">No scans yet — run one above and it'll be saved here.</div>`;
      return;
    }
    historyList.innerHTML = scans.map(historyRow).join('');
    historyList.querySelectorAll('[data-open]').forEach(b => b.addEventListener('click', () => openScan(b.dataset.open)));
    historyList.querySelectorAll('[data-del]').forEach(b => b.addEventListener('click', () => deleteScan(b.dataset.del)));
  } catch (e) {
    historyList.innerHTML = `<div class="history-empty">Couldn't load history.</div>`;
  }
}

async function openScan(id) {
  try {
    const scan = await (await fetch(api(`/api/job/${id}`))).json();
    switchMode(scan.kind === 'audit' ? 'audit' : 'recon');
    renderResult(scan);
    setState('done', 'Loaded');
  } catch (e) { /* ignore */ }
}

async function deleteScan(id) {
  try {
    await fetch(api(`/api/history/${id}`), { method: 'DELETE' });
    if (currentScanId === id) { resultsDiv.innerHTML = ''; currentScanId = null; }
    loadHistory();
  } catch (e) { /* ignore */ }
}

historyRefresh.addEventListener('click', loadHistory);

/* ============================================================
   INIT
   ============================================================ */
switchMode('audit');   // Code Audit is the landing view
loadHistory();


/*Hello i am back */
