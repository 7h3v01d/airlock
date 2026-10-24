# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)

"""
airlock.dashboard.server

FastAPI dashboard server for Airlock.
Read-only observability over the pipeline.

Run via: airlock dashboard [--port 7842]
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

import re
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from airlock.dashboard.reader import ProjectReader

_CANDIDATE_ID_RE = re.compile(r"^candidate_[0-9]{4,}$")

# ── App ───────────────────────────────────────────────────────────────────────

def create_app(project_root: Path) -> FastAPI:
    app = FastAPI(
        title="Airlock Dashboard",
        description="Read-only observability over the cleanroom pipeline.",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    reader = ProjectReader(project_root)

    # ── API routes ────────────────────────────────────────────────────────────

    @app.get("/api/overview")
    def api_overview() -> JSONResponse:
        return JSONResponse(asdict(reader.overview()))

    @app.get("/api/specs")
    def api_specs() -> JSONResponse:
        return JSONResponse([asdict(s) for s in reader.specs()])

    @app.get("/api/candidates")
    def api_candidates() -> JSONResponse:
        return JSONResponse([asdict(c) for c in reader.candidates()])

    @app.get("/api/candidates/{candidate_id}")
    def api_candidate_detail(candidate_id: str) -> JSONResponse:
        if not _CANDIDATE_ID_RE.fullmatch(candidate_id):
            raise HTTPException(status_code=400, detail="Invalid candidate id")
        detail = reader.candidate_detail(candidate_id)
        if not detail:
            raise HTTPException(status_code=404, detail="Candidate not found")
        return JSONResponse(asdict(detail))

    @app.get("/api/audit")
    def api_audit() -> JSONResponse:
        return JSONResponse([asdict(e) for e in reader.audit_log()])

    @app.get("/api/llm-calls")
    def api_llm_calls() -> JSONResponse:
        return JSONResponse(reader.llm_calls())

    # ── UI ────────────────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def dashboard_ui() -> str:
        return _DASHBOARD_HTML

    return app


# ── Dashboard HTML ────────────────────────────────────────────────────────────

_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Airlock</title>
<style>
  :root {
    --bg: #0b0f14; --surface: #11161d; --surface2: #161d26;
    --border: #1e2831; --text: #c8d3da; --muted: #7b8a95;
    --cyan: #2fd6c3; --green: #4be08a; --red: #ff6b6b;
    --yellow: #ffb454; --purple: #b79cff; --orange: #ffb454;
    --blue: #2fd6c3;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', ui-monospace, Consolas, 'Cascadia Mono', monospace; font-size: 14px; min-height: 100vh; }
  a { color: var(--cyan); text-decoration: none; }
  button, input, select { font-family: inherit; }
  a:hover { text-decoration: underline; }

  /* Layout */
  .shell { display: flex; min-height: 100vh; }
  .sidebar { width: 220px; background: var(--surface); border-right: 1px solid var(--border); padding: 0; flex-shrink: 0; position: fixed; top: 0; bottom: 0; overflow-y: auto; }
  .main { margin-left: 220px; flex: 1; padding: 28px 32px; max-width: 1200px; }

  /* Sidebar */
  .sidebar-brand { padding: 20px 18px 14px; border-bottom: 1px solid var(--border); }
  .sidebar-brand h1 { font-size: 13px; font-weight: 700; color: var(--cyan); letter-spacing: .5px; text-transform: uppercase; }
  .sidebar-brand p { font-size: 11px; color: var(--muted); margin-top: 3px; }
  .nav { padding: 10px 0; }
  .nav-item { display: flex; align-items: center; gap: 10px; padding: 9px 18px; cursor: pointer; color: var(--muted); font-size: 13px; border-left: 3px solid transparent; transition: all .15s; }
  .nav-item:hover { background: var(--surface2); color: var(--text); }
  .nav-item.active { color: var(--cyan); border-left-color: var(--cyan); background: rgba(47,214,195,.07); }
  .nav-icon { font-size: 15px; width: 18px; text-align: center; }

  /* Header */
  .page-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 24px; }
  .page-header h2 { font-size: 20px; font-weight: 600; }
  .refresh-btn { padding: 6px 14px; background: var(--surface2); border: 1px solid var(--border); border-radius: 0; color: var(--text); cursor: pointer; font-size: 12px; transition: border-color .15s; }
  .refresh-btn:hover { border-color: var(--cyan); color: var(--cyan); }

  /* Cards */
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 0; padding: 18px 20px; }
  .stat-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .7px; margin-bottom: 8px; }
  .stat-card .value { font-size: 28px; font-weight: 700; }
  .stat-card .sub { font-size: 11px; color: var(--muted); margin-top: 4px; }

  /* Tables */
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 0; overflow: hidden; margin-bottom: 24px; }
  .card-header { padding: 14px 20px; border-bottom: 1px solid var(--border); font-weight: 600; font-size: 13px; display: flex; align-items: center; justify-content: space-between; }
  .card-header .count { font-size: 11px; color: var(--muted); font-weight: 400; }
  table { width: 100%; border-collapse: collapse; }
  th { padding: 10px 16px; text-align: left; font-size: 11px; color: var(--muted); font-weight: 500; text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid var(--border); background: var(--surface2); }
  td { padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 13px; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,.02); }

  /* Badges */
  .badge { display: inline-flex; align-items: center; gap: 4px; padding: 2px 9px; border-radius: 0; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .badge-green { background: rgba(75,224,138,.15); color: var(--green); }
  .badge-red { background: rgba(255,107,107,.15); color: var(--red); }
  .badge-yellow { background: rgba(255,180,84,.15); color: var(--yellow); }
  .badge-blue { background: rgba(47,214,195,.15); color: var(--blue); }
  .badge-purple { background: rgba(188,140,255,.15); color: var(--purple); }
  .badge-orange { background: rgba(255,180,84,.15); color: var(--orange); }
  .badge-muted { background: rgba(139,148,158,.1); color: var(--muted); }

  /* Evidence grid */
  .evidence-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 10px; padding: 16px 20px; }
  .ev-card { background: var(--surface2); border: 1px solid var(--border); border-radius: 0; padding: 12px 14px; }
  .ev-card .doc-name { font-size: 11px; color: var(--muted); margin-bottom: 6px; word-break: break-all; }
  .ev-card .doc-status { font-size: 13px; font-weight: 600; }
  .ev-card .doc-verdict { font-size: 11px; color: var(--muted); margin-top: 4px; }
  .ev-card .sidecar-ok { font-size: 10px; margin-top: 6px; }

  /* Audit log */
  .audit-entry { padding: 12px 20px; border-bottom: 1px solid var(--border); display: flex; gap: 16px; align-items: flex-start; }
  .audit-entry:last-child { border-bottom: none; }
  .audit-time { font-size: 11px; color: var(--muted); white-space: nowrap; min-width: 150px; padding-top: 1px; font-family: monospace; }
  .audit-body { flex: 1; }
  .audit-event { font-weight: 600; font-size: 13px; margin-bottom: 4px; }
  .audit-meta { font-size: 11px; color: var(--muted); display: flex; gap: 12px; flex-wrap: wrap; }
  .audit-reasons { margin-top: 6px; }
  .audit-reasons li { font-size: 11px; color: var(--muted); list-style: none; padding: 1px 0; }
  .audit-reasons li::before { content: '• '; color: var(--red); }

  /* Detail view */
  .detail-back { margin-bottom: 20px; font-size: 13px; }
  .detail-hero { background: var(--surface); border: 1px solid var(--border); border-radius: 0; padding: 24px; margin-bottom: 20px; }
  .detail-hero h3 { font-size: 18px; font-weight: 700; margin-bottom: 12px; font-family: monospace; }
  .detail-meta { display: flex; gap: 24px; flex-wrap: wrap; }
  .detail-meta-item { font-size: 12px; }
  .detail-meta-item .key { color: var(--muted); margin-bottom: 2px; }
  .detail-meta-item .val { font-weight: 600; }

  /* Hash display */
  .hash { font-family: monospace; font-size: 11px; color: var(--muted); }
  .hash-short { font-family: monospace; font-size: 11px; color: var(--cyan); }

  /* Empty state */
  .empty { padding: 40px; text-align: center; color: var(--muted); }
  .empty .icon { font-size: 32px; margin-bottom: 12px; }
  .empty p { font-size: 13px; }

  /* Loading */
  .loading { padding: 40px; text-align: center; color: var(--muted); font-size: 13px; }

  /* Candidate row clickable */
  .clickable { cursor: pointer; }
  .clickable:hover td { background: rgba(121,192,255,.05) !important; }

  /* Scrollable log */
  .log-scroll { max-height: 480px; overflow-y: auto; }
</style>
</head>
<body>
<div class="shell">

<!-- Sidebar -->
<aside class="sidebar">
  <div class="sidebar-brand">
    <h1>Airlock</h1>
    <p id="project-name">Loading...</p>
  </div>
  <nav class="nav">
    <div class="nav-item active" onclick="showPage('overview')" id="nav-overview">
      <span class="nav-icon">⬡</span> Overview
    </div>
    <div class="nav-item" onclick="showPage('candidates')" id="nav-candidates">
      <span class="nav-icon">◈</span> Candidates
    </div>
    <div class="nav-item" onclick="showPage('specs')" id="nav-specs">
      <span class="nav-icon">◻</span> Specs
    </div>
    <div class="nav-item" onclick="showPage('audit')" id="nav-audit">
      <span class="nav-icon">≡</span> Audit Log
    </div>
    <div class="nav-item" onclick="showPage('llm')" id="nav-llm">
      <span class="nav-icon">✦</span> LLM Calls
    </div>
  </nav>
</aside>

<!-- Main -->
<main class="main" id="main-content">
  <div class="loading">Loading dashboard...</div>
</main>

</div>
<script>
// ── Security ──────────────────────────────────────────────────────────────────
function escapeHtml(v) {
  return String(v ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

// ── State ─────────────────────────────────────────────────────────────────────
let state = {
  page: 'overview',
  overview: null,
  specs: null,
  candidates: null,
  audit: null,
  llm: null,
  selectedCandidate: null,
};

// ── API ───────────────────────────────────────────────────────────────────────
async function api(endpoint) {
  const r = await fetch('/api/' + endpoint);
  if (!r.ok) throw new Error('API error: ' + r.status);
  return r.json();
}

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(page) {
  state.page = page;
  state.selectedCandidate = null;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById('nav-' + page)?.classList.add('active');
  render();
}

// ── Render ────────────────────────────────────────────────────────────────────
async function render() {
  const el = document.getElementById('main-content');
  el.innerHTML = '<div class="loading">Loading...</div>';

  try {
    if (state.page === 'overview') await renderOverview(el);
    else if (state.page === 'candidates') await renderCandidates(el);
    else if (state.page === 'candidate-detail') await renderCandidateDetail(el);
    else if (state.page === 'specs') await renderSpecs(el);
    else if (state.page === 'audit') await renderAudit(el);
    else if (state.page === 'llm') await renderLLM(el);
  } catch(e) {
    el.innerHTML = '<div class="empty"><div class="icon">⚠</div><p>Error: ' + e.message + '</p></div>';
  }
}

// ── Overview ──────────────────────────────────────────────────────────────────
async function renderOverview(el) {
  const ov = await api('overview');
  state.overview = ov;
  document.getElementById('project-name').textContent = ov.project_name;

  const statusColors = {admitted:'green', certified:'blue', verified:'purple', quarantined:'yellow', rejected:'red'};
  const statusRows = Object.entries(ov.by_status).map(([s, n]) => `
    <tr>
      <td>${statusBadge(s)}</td>
      <td style="text-align:right;font-weight:700">${n}</td>
    </tr>`).join('');

  el.innerHTML = `
    <div class="page-header">
      <h2>Overview</h2>
      <button class="refresh-btn" onclick="render()">↻ Refresh</button>
    </div>

    <div class="stat-grid">
      <div class="stat-card">
        <div class="label">Project</div>
        <div class="value" style="font-size:18px;padding-top:4px">${escapeHtml(ov.project_name)}</div>
        <div class="sub">Risk class: ${escapeHtml(ov.risk_class)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Specs</div>
        <div class="value" style="color:var(--cyan)">${ov.total_specs}</div>
        <div class="sub">${ov.locked_specs} locked</div>
      </div>
      <div class="stat-card">
        <div class="label">Candidates</div>
        <div class="value">${ov.total_candidates}</div>
        <div class="sub">${ov.admitted_count} admitted</div>
      </div>
      <div class="stat-card">
        <div class="label">Last Activity</div>
        <div class="value" style="font-size:13px;padding-top:8px">${formatDate(ov.last_activity)}</div>
        <div class="sub">${formatTime(ov.last_activity)}</div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">Pipeline Status</div>
      <table>
        <thead><tr><th>Status</th><th style="text-align:right">Count</th></tr></thead>
        <tbody>${statusRows || '<tr><td colspan="2" style="color:var(--muted);text-align:center">No candidates yet</td></tr>'}</tbody>
      </table>
    </div>`;
}

// ── Candidates ────────────────────────────────────────────────────────────────
async function renderCandidates(el) {
  const candidates = await api('candidates');
  state.candidates = candidates;

  const rows = candidates.map(c => `
    <tr class="clickable" onclick="showCandidate('${c.candidate_id}')">
      <td><span class="hash-short">${c.candidate_id}</span></td>
      <td><span class="hash-short">${c.spec_id}</span></td>
      <td>${statusBadge(c.status)}</td>
      <td>${c.generated_by === 'manual' ? '<span class="badge badge-muted">manual</span>' : '<span class="badge badge-purple">🤖 ' + shortModel(c.generated_by) + '</span>'}</td>
      <td>${evidenceSummaryBadges(c.evidence)}</td>
      <td style="color:var(--muted);font-size:11px">${formatDate(c.registered_at)}</td>
    </tr>`).join('');

  el.innerHTML = `
    <div class="page-header">
      <h2>Candidates</h2>
      <button class="refresh-btn" onclick="render()">↻ Refresh</button>
    </div>
    <div class="card">
      <div class="card-header">All Candidates <span class="count">${candidates.length} total</span></div>
      <table>
        <thead><tr><th>ID</th><th>Spec</th><th>Status</th><th>Origin</th><th>Evidence</th><th>Registered</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="empty">No candidates registered yet.</td></tr>'}</tbody>
      </table>
    </div>`;
}

async function showCandidate(id) {
  state.selectedCandidate = id;
  state.page = 'candidate-detail';
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById('nav-candidates')?.classList.add('active');
  await render();
}

async function renderCandidateDetail(el) {
  const c = await api('candidates/' + state.selectedCandidate);

  const evidenceCards = c.evidence.map(e => {
    const color = !e.present ? 'muted' : !e.sidecar_ok ? 'red' : verdictColor(e.verdict);
    const icon = !e.present ? '○' : !e.sidecar_ok ? '!' : '✓';
    return `<div class="ev-card">
      <div class="doc-name">${e.document}</div>
      <div class="doc-status" style="color:var(--${color})">${icon} ${e.present ? (e.verdict || 'present') : 'missing'}</div>
      ${e.verdict ? '<div class="doc-verdict">' + e.verdict + '</div>' : ''}
      <div class="sidecar-ok" style="color:var(--${e.sidecar_ok ? 'green' : (e.present ? 'red' : 'muted')})">
        ${e.present ? (e.sidecar_ok ? '✓ sidecar verified' : '✗ ' + e.sidecar_msg) : ''}
      </div>
    </div>`;
  }).join('');

  const certSection = c.certificate_id ? `
    <div class="card" style="border-color:var(--green)">
      <div class="card-header" style="color:var(--green)">⬡ Admission Certificate</div>
      <div style="padding:16px 20px;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px">
        <div class="detail-meta-item"><div class="key">Certificate ID</div><div class="val" style="font-family:monospace;font-size:12px">${escapeHtml(c.certificate_id)}</div></div>
        <div class="detail-meta-item"><div class="key">Level</div><div class="val" style="color:var(--green)">${c.level}</div></div>
        <div class="detail-meta-item"><div class="key">Admitted</div><div class="val">${formatDate(c.admitted_at)} ${formatTime(c.admitted_at)}</div></div>
        ${c.operator_override ? '<div class="detail-meta-item"><div class="key">Operator override</div><div class="val" style="color:var(--yellow)">' + escapeHtml(c.override_operator) + ' — ' + escapeHtml(c.override_reason) + '</div></div>' : ''}
      </div>
    </div>` : '';

  el.innerHTML = `
    <div class="detail-back"><a href="#" onclick="showPage('candidates')">← Back to Candidates</a></div>
    <div class="detail-hero">
      <h3>${escapeHtml(c.candidate_id)}</h3>
      <div class="detail-meta">
        <div class="detail-meta-item"><div class="key">Status</div><div class="val">${statusBadge(c.status)}</div></div>
        <div class="detail-meta-item"><div class="key">Spec</div><div class="val" style="font-family:monospace">${c.spec_id}</div></div>
        <div class="detail-meta-item"><div class="key">Language</div><div class="val">${c.language}</div></div>
        <div class="detail-meta-item"><div class="key">Origin</div><div class="val">${c.generated_by}</div></div>
        <div class="detail-meta-item"><div class="key">Source Hash</div><div class="val hash">${c.source_hash ? escapeHtml(c.source_hash).substring(0,30) + '...' : '—'}</div></div>
        <div class="detail-meta-item"><div class="key">Registered</div><div class="val">${formatDate(c.registered_at)}</div></div>
      </div>
    </div>
    ${certSection}
    <div class="card">
      <div class="card-header">Evidence Chain</div>
      <div class="evidence-grid">${evidenceCards}</div>
    </div>`;
}

// ── Specs ─────────────────────────────────────────────────────────────────────
async function renderSpecs(el) {
  const specs = await api('specs');
  const rows = specs.map(s => `
    <tr>
      <td><span class="hash-short">${s.spec_id}</span></td>
      <td>${escapeHtml(s.description)}</td>
      <td>${s.status === 'LOCKED'
        ? '<span class="badge badge-green">LOCKED</span>'
        : '<span class="badge badge-yellow">DRAFT</span>'}</td>
      <td class="hash">${s.spec_hash ? escapeHtml(s.spec_hash).substring(0,20) + '...' : '—'}</td>
      <td style="color:var(--muted);font-size:11px">${formatDate(s.locked_at || s.created_at)}</td>
    </tr>`).join('');

  el.innerHTML = `
    <div class="page-header">
      <h2>Specifications</h2>
      <button class="refresh-btn" onclick="render()">↻ Refresh</button>
    </div>
    <div class="card">
      <div class="card-header">All Specs <span class="count">${specs.length} total</span></div>
      <table>
        <thead><tr><th>ID</th><th>Description</th><th>Status</th><th>Hash</th><th>Date</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="empty">No specs created yet.</td></tr>'}</tbody>
      </table>
    </div>`;
}

// ── Audit Log ─────────────────────────────────────────────────────────────────
async function renderAudit(el) {
  const entries = await api('audit');

  const items = entries.map(e => {
    const eventColor = e.event === 'candidate_admitted' ? 'green'
      : e.event === 'gate_decision' && e.decision === 'ALLOW' ? 'blue'
      : e.event === 'gate_decision' && e.decision === 'DENY' ? 'red'
      : e.event === 'gate_decision' && e.decision === 'ESCALATE_TO_OPERATOR' ? 'purple'
      : e.event === 'operator_override' ? 'yellow'
      : 'muted';

    const reasons = e.reasons?.length ? `<ul class="audit-reasons">${e.reasons.map(r => '<li>' + escapeHtml(r) + '</li>').join('')}</ul>` : '';

    return `<div class="audit-entry">
      <div class="audit-time">${e.timestamp.substring(0,19).replace('T',' ')}</div>
      <div class="audit-body">
        <div class="audit-event" style="color:var(--${eventColor})">${eventIcon(e.event)} ${e.event}</div>
        <div class="audit-meta">
          ${e.candidate_id ? '<span>candidate: <b>' + escapeHtml(e.candidate_id) + '</b></span>' : ''}
          ${e.spec_id ? '<span>spec: <b>' + escapeHtml(e.spec_id) + '</b></span>' : ''}
          ${e.decision ? '<span>decision: ' + decisionBadge(e.decision) + '</span>' : ''}
          ${e.overridden_decision ? '<span>overrode: ' + decisionBadge(e.overridden_decision) + '</span>' : ''}
          ${e.gate_id ? '<span>gate: <code>' + escapeHtml(e.gate_id) + '</code></span>' : ''}
          ${e.certificate_id ? '<span>cert: <code>' + escapeHtml(e.certificate_id) + '</code></span>' : ''}
          ${e.operator_id ? '<span>operator: ' + escapeHtml(e.operator_id) + '</span>' : ''}
        </div>
        ${e.reason ? '<div class="audit-meta"><span>reason: ' + escapeHtml(e.reason) + '</span></div>' : ''}
        ${reasons}
      </div>
    </div>`;
  }).join('');

  el.innerHTML = `
    <div class="page-header">
      <h2>Audit Log</h2>
      <button class="refresh-btn" onclick="render()">↻ Refresh</button>
    </div>
    <div class="card">
      <div class="card-header">All Events <span class="count">${entries.length} entries · most recent first</span></div>
      <div class="log-scroll">${items || '<div class="empty"><div class="icon">≡</div><p>No audit events yet.</p></div>'}</div>
    </div>`;
}

// ── LLM Calls ─────────────────────────────────────────────────────────────────
async function renderLLM(el) {
  const calls = await api('llm-calls');

  const rows = calls.map(c => `
    <tr>
      <td style="font-size:11px;color:var(--muted);font-family:monospace">${c.timestamp?.substring(0,19).replace('T',' ') || '—'}</td>
      <td><span class="badge badge-purple">${escapeHtml(c.role) || '—'}</span></td>
      <td style="font-size:12px">${escapeHtml(c.model) || '—'}</td>
      <td style="font-family:monospace;font-size:11px;color:var(--cyan)">${escapeHtml(c.prompt_hash || '').substring(0,24)}...</td>
      <td style="font-size:11px;color:var(--muted)">${c.token_estimate ? c.token_estimate + ' tok' : '—'}</td>
      <td style="font-size:11px;color:var(--muted)">${c.latency_ms ? (c.latency_ms/1000).toFixed(1) + 's' : '—'}</td>
      <td>${c.success ? '<span class="badge badge-green">✓</span>' : '<span class="badge badge-red">✗</span>'}</td>
    </tr>`).join('');

  el.innerHTML = `
    <div class="page-header">
      <h2>LLM Call Log</h2>
      <button class="refresh-btn" onclick="render()">↻ Refresh</button>
    </div>
    <p style="color:var(--muted);font-size:12px;margin-bottom:16px">Raw prompts and responses are never logged — only hashes. All calls were to a local Ollama instance.</p>
    <div class="card">
      <div class="card-header">All LLM Calls <span class="count">${calls.length} total · most recent first</span></div>
      <table>
        <thead><tr><th>Timestamp</th><th>Role</th><th>Model</th><th>Prompt Hash</th><th>Tokens</th><th>Latency</th><th>OK</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="empty">No LLM calls recorded yet.</td></tr>'}</tbody>
      </table>
    </div>`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function statusBadge(s) {
  const map = {
    admitted:    'badge-green',
    certified:   'badge-blue',
    verified:    'badge-purple',
    quarantined: 'badge-yellow',
    rejected:    'badge-red',
    LOCKED:      'badge-green',
    DRAFT:       'badge-yellow',
  };
  return `<span class="badge ${map[s] || 'badge-muted'}">${s}</span>`;
}

function decisionBadge(d) {
  const map = {ALLOW:'badge-green', DENY:'badge-red', QUARANTINE:'badge-yellow', ESCALATE_TO_OPERATOR:'badge-orange'};
  return `<span class="badge ${map[d] || 'badge-muted'}">${d}</span>`;
}

function verdictColor(v) {
  if (!v) return 'muted';
  if (v === 'PASS' || v === 'CERTIFIED' || v === 'ALLOW' || v.includes('L4')) return 'green';
  if (v === 'FAIL' || v === 'NOT_CERTIFIED' || v === 'DENY') return 'red';
  if (v === 'QUARANTINE') return 'yellow';
  return 'cyan';
}

function evidenceSummaryBadges(evidence) {
  if (!evidence?.length) return '<span class="badge badge-muted">none</span>';
  const present = evidence.filter(e => e.present);
  const allOk = present.every(e => e.sidecar_ok);
  const hasAdmission = evidence.find(e => e.document === 'admission_certificate.json' && e.present);
  const hasGate = evidence.find(e => e.document === 'gate_decision.json' && e.present);
  if (hasAdmission) return '<span class="badge badge-green">✓ L4 admitted</span>';
  if (hasGate) return '<span class="badge badge-blue">gate decided</span>';
  if (!allOk) return '<span class="badge badge-red">⚠ integrity</span>';
  return `<span class="badge badge-muted">${present.length} docs</span>`;
}

function eventIcon(event) {
  const map = {candidate_admitted:'🏆', gate_decision:'⬡', operator_override:'⚑'};
  return map[event] || '●';
}

function shortModel(s) {
  return s.replace('ollama:', '').split(':')[0].substring(0,18);
}

function formatDate(ts) {
  if (!ts) return '—';
  return ts.substring(0,10);
}

function formatTime(ts) {
  if (!ts) return '';
  return ts.substring(11,19) + ' UTC';
}

// ── Init ──────────────────────────────────────────────────────────────────────
render();
</script>
</body>
</html>"""
