/**
 * Azure ARM Security Analyzer - AI Threat Intelligence & Attack-Path Controller
 * Manages attack-path synthesis, server-side caching, UI timeline rendering,
 * and topology visualizer path highlighting.
 */

let activeAttackPaths = [];
let selectedPathId = null;

document.addEventListener('DOMContentLoaded', () => {
  setupRightPaneTabs();
  setupThreatModelTriggers();
  checkAiStatus();
});

function setupRightPaneTabs() {
  const btnAudit = document.getElementById('tabAuditFindings');
  const btnAi = document.getElementById('tabAiThreats');
  const viewAudit = document.getElementById('viewAuditFindings');
  const viewAi = document.getElementById('viewAiThreats');

  if (!btnAudit || !btnAi || !viewAudit || !viewAi) return;

  btnAudit.addEventListener('click', () => {
    btnAudit.classList.add('active');
    btnAi.classList.remove('active');
    viewAudit.classList.remove('hidden');
    viewAi.classList.add('hidden');
  });

  btnAi.addEventListener('click', () => {
    btnAi.classList.add('active');
    btnAudit.classList.remove('active');
    viewAi.classList.remove('hidden');
    viewAudit.classList.add('hidden');

    // Auto-load if not loaded yet
    if (activeAttackPaths.length === 0 && !window.aiThreatsLoading) {
      loadAiThreatModel(false);
    }
  });
}

function setupThreatModelTriggers() {
  const btnRun = document.getElementById('btnRunThreatModel');
  if (btnRun) {
    btnRun.addEventListener('click', () => {
      loadAiThreatModel(true);
    });
  }

  const btnClearHighlight = document.getElementById('btnClearAttackPath');
  if (btnClearHighlight) {
    btnClearHighlight.addEventListener('click', () => {
      if (typeof window.clearAttackPathHighlight === 'function') {
        window.clearAttackPathHighlight();
      }
      document.querySelectorAll('.attack-path-card').forEach(c => c.classList.remove('selected-path'));
      btnClearHighlight.classList.add('hidden');
    });
  }
}

function checkAiStatus() {
  // Status indicator removed per user request
}

function loadAiThreatModel(forceRefresh = false) {
  const fileId = window.FILE_ID;
  if (!fileId) return;

  const container = document.getElementById('aiThreatsListContainer');
  const btnRun = document.getElementById('btnRunThreatModel');
  const badge = document.getElementById('aiThreatCountBadge');
  window.aiThreatsLoading = true;

  if (btnRun) {
    btnRun.disabled = true;
    btnRun.innerHTML = `<span>⏳</span> Analyzing Attack Paths...`;
  }

  if (container) {
    container.innerHTML = `
      <div class="ai-loading-state">
        <div class="ai-spinner"></div>
        <p class="ai-loading-title">Synthesizing Infrastructure Threat Model...</p>
        <p class="ai-loading-sub">Correlating open ports, NSG boundaries, identity permissions, and data flow channels.</p>
      </div>
    `;
  }

  const url = `/api/ai/threat-model/${fileId}${forceRefresh ? '?refresh=true' : ''}`;

  fetch(url, { method: 'POST' })
    .then(res => res.json())
    .then(data => {
      window.aiThreatsLoading = false;
      if (btnRun) {
        btnRun.disabled = false;
        btnRun.innerHTML = `<span>🔄</span> Refresh Threat Model`;
      }

      if (!data.success) {
        renderAiError(container, data.error, data.code);
        return;
      }

      activeAttackPaths = data.attack_paths || [];
      if (badge) {
        badge.textContent = activeAttackPaths.length;
        badge.className = activeAttackPaths.length > 0 ? 'badge badge-danger' : 'badge badge-subtle';
      }

      renderAttackPaths(container, activeAttackPaths, data.cached);
    })
    .catch(err => {
      window.aiThreatsLoading = false;
      if (btnRun) {
        btnRun.disabled = false;
        btnRun.innerHTML = `<span>🔄</span> Retry Threat Model`;
      }
      renderAiError(container, "Network error reaching AI analysis endpoint: " + err, "NETWORK_ERROR");
    });
}

function renderAttackPaths(container, paths, isCached) {
  if (!container) return;
  container.innerHTML = '';

  if (paths.length === 0) {
    container.innerHTML = `
      <div class="ai-empty-state">
        <span class="ai-empty-icon">🛡️</span>
        <h3>No Correlated Attack Paths Detected</h3>
        <p>The AI model did not identify a viable lateral movement path from external entry points to critical assets based on current configuration evidence.</p>
      </div>
    `;
    return;
  }

  const headerNotice = document.createElement('div');
  headerNotice.className = 'ai-paths-header-notice';
  headerNotice.innerHTML = `
    <span>⚡ Identified <strong>${paths.length} Potential Attack Path${paths.length > 1 ? 's' : ''}</strong></span>
    ${isCached ? '<span class="badge badge-subtle">Cached Result</span>' : '<span class="badge badge-success">Fresh AI Analysis</span>'}
  `;
  container.appendChild(headerNotice);

  paths.forEach((path, idx) => {
    const card = document.createElement('div');
    const riskClass = (path.risk || 'MEDIUM').toLowerCase();
    card.className = `attack-path-card border-risk-${riskClass}`;
    card.setAttribute('data-path-id', path.id);

    const stepsHtml = (path.steps || []).map(s => `
      <div class="path-step-item">
        <div class="step-marker">${s.step}</div>
        <div class="step-content">
          <div class="step-res-line">
            <span class="step-res-id" title="${escapeHtml(s.resource_id)}">${escapeHtml(shortenResourceId(s.resource_id))}</span>
          </div>
          <div class="step-desc">${escapeHtml(s.description)}</div>
          ${s.evidence && s.evidence.length ? `
            <div class="step-evidence">
              <span>Evidence:</span> ${escapeHtml(s.evidence.join('; '))}
            </div>
          ` : ''}
          ${s.preconditions && s.preconditions.length ? `
            <div class="step-preconditions">
              <span>Preconditions:</span> ${escapeHtml(s.preconditions.join('; '))}
            </div>
          ` : ''}
        </div>
      </div>
    `).join('');

    card.innerHTML = `
      <div class="path-card-header">
        <div class="path-title-row">
          <span class="pill pill-${riskClass}">${path.risk}</span>
          <span class="badge badge-subtle">${path.evidence_strength || 'CONFIGURATION_SUPPORTED'}</span>
          <span class="path-title">${escapeHtml(path.title)}</span>
        </div>
        <button class="btn btn-sm btn-cyan btn-highlight-path" data-path-idx="${idx}">
          <span>🎯 Highlight in Graph</span>
        </button>
      </div>

      <p class="path-summary">${escapeHtml(path.summary)}</p>

      <div class="path-steps-timeline">
        ${stepsHtml}
      </div>

      <div class="path-footer-meta">
        <div><strong>Impact:</strong> ${escapeHtml(path.impact || 'Unauthorized access')}</div>
        ${path.recommendations && path.recommendations.length ? `
          <div class="path-recommendation"><strong>Mitigation:</strong> ${escapeHtml(path.recommendations[0])}</div>
        ` : ''}
      </div>
    `;

    const highlightBtn = card.querySelector('.btn-highlight-path');
    if (highlightBtn) {
      highlightBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        selectAndHighlightPath(path, card);
      });
    }

    container.appendChild(card);
  });
}

function selectAndHighlightPath(path, cardEl) {
  selectedPathId = path.id;

  document.querySelectorAll('.attack-path-card').forEach(c => c.classList.remove('selected-path'));
  if (cardEl) cardEl.classList.add('selected-path');

  const btnClear = document.getElementById('btnClearAttackPath');
  if (btnClear) btnClear.classList.remove('hidden');

  if (typeof window.highlightAttackPath === 'function') {
    window.highlightAttackPath(path);
  }
}

function renderAiError(container, message, code) {
  if (!container) return;

  let helpHint = "";
  const isOllama = (message && message.toLowerCase().includes("ollama")) || code === "MODEL_NOT_FOUND" || code === "CONNECTION_FAILED";

  if (isOllama) {
    helpHint = `
      <div class="ai-help-box">
        <strong>Ollama Local Setup:</strong>
        <p>1. Start the daemon: <code>ollama serve</code></p>
        <p>2. Pull your chosen model: <code>ollama pull &lt;model&gt;</code> (e.g. qwen, mistral, llama3.2)</p>
        <p>3. Configure <code>OLLAMA_MODEL=&lt;model&gt;</code> in <code>.env</code></p>
      </div>
    `;
  } else if (code === "AI_UNCONFIGURED" || code === "AUTH_FAILED") {
    helpHint = `
      <div class="ai-help-box">
        <strong>Setup Guide:</strong>
        <p>1. Open <code>.env</code> in your project directory.</p>
        <p>2. Set <code>GEMINI_API_KEY=your_gemini_api_key_here</code> or switch to <code>AI_PROVIDER=ollama</code>.</p>
        <p>3. Restart the server or refresh this view.</p>
      </div>
    `;
  } else if (code === "QUOTA_EXCEEDED") {
    helpHint = `
      <div class="ai-help-box">
        <p>Your Google Gemini API quota has been reached. You can switch to local inference by setting <code>AI_PROVIDER=ollama</code> in <code>.env</code>, or inspect deterministic findings.</p>
      </div>
    `;
  }

  container.innerHTML = `
    <div class="ai-error-banner">
      <span class="ai-error-icon">⚠️</span>
      <div class="ai-error-body">
        <h4>AI Analysis Unavailable</h4>
        <p>${escapeHtml(message)}</p>
        ${helpHint}
      </div>
    </div>
  `;
}

function shortenResourceId(fullId) {
  if (!fullId) return "";
  const parts = fullId.split('/');
  return parts[parts.length - 1];
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

window.explainFinding = function(findingId, containerEl) {
  if (!containerEl) return;
  const fileId = window.FILE_ID;
  if (!fileId) return;

  containerEl.style.display = 'block';
  containerEl.innerHTML = `
    <div class="ai-loading-state" style="padding: 1rem;">
      <div class="ai-spinner" style="width: 22px; height: 22px;"></div>
      <p class="ai-loading-title" style="font-size: 0.82rem;">Synthesizing Architectural Context...</p>
    </div>
  `;

  fetch(`/api/ai/explain/${fileId}/${encodeURIComponent(findingId)}`, { method: 'POST' })
    .then(res => res.json())
    .then(data => {
      if (!data.success) {
        containerEl.innerHTML = `<span style="color:#f87171;">⚠️ ${escapeHtml(data.error || 'Failed generating explanation.')}</span>`;
        return;
      }
      const exp = data.explanation || {};
      const stepsHtml = (exp.verification_steps || []).map(s => `<li>${escapeHtml(s)}</li>`).join('');

      containerEl.innerHTML = `
        <div class="ai-insight-panel">
          <div class="ai-insight-title">
            <span>⚡ AI Architectural Analysis</span>
            ${exp.cached ? '<span class="badge badge-subtle">Cached</span>' : '<span class="badge badge-success">Fresh</span>'}
          </div>
          <div class="ai-insight-section">
            <strong>Risk Summary:</strong>
            <p>${escapeHtml(exp.summary)}</p>
          </div>
          <div class="ai-insight-section">
            <strong>Architecture & Blast Radius:</strong>
            <p>${escapeHtml(exp.architectural_context)}</p>
          </div>
          <div class="ai-insight-section">
            <strong>Attacker Perspective:</strong>
            <p>${escapeHtml(exp.attacker_perspective)}</p>
          </div>
          ${stepsHtml ? `
            <div class="ai-insight-section">
              <strong>Verification Steps:</strong>
              <ol style="padding-left: 1.15rem; margin-top: 0.2rem;">${stepsHtml}</ol>
            </div>
          ` : ''}
          <div class="ai-insight-section" style="border-top: 1px solid rgba(255,255,255,0.06); padding-top: 0.35rem;">
            <strong style="color: #34d399;">Remediation Recommendation:</strong>
            <p>${escapeHtml(exp.quick_fix_summary)}</p>
          </div>
        </div>
      `;
    })
    .catch(err => {
      containerEl.innerHTML = `<span style="color:#f87171;">⚠️ Network error: ${escapeHtml(err.message || String(err))}</span>`;
    });
};

window.remediateFinding = function(findingId, containerEl) {
  if (!containerEl) return;
  const fileId = window.FILE_ID;
  if (!fileId) return;

  containerEl.style.display = 'block';
  containerEl.innerHTML = `
    <div class="ai-loading-state" style="padding: 1rem;">
      <div class="ai-spinner" style="width: 22px; height: 22px;"></div>
      <p class="ai-loading-title" style="font-size: 0.82rem;">Generating ARM JSON Patch...</p>
    </div>
  `;

  fetch(`/api/ai/remediate/${fileId}/${encodeURIComponent(findingId)}`, { method: 'POST' })
    .then(res => res.json())
    .then(data => {
      if (!data.success) {
        containerEl.innerHTML = `<span style="color:#f87171;">⚠️ ${escapeHtml(data.error || 'Failed generating remediation patch.')}</span>`;
        return;
      }
      const rem = data.remediation || {};
      const patchProps = rem.suggested_properties_patch || {};

      containerEl.innerHTML = `
        <div class="ai-insight-panel">
          <div class="ai-insight-title">
            <span>🛠️ AI Remediation Patch</span>
            ${rem.cached ? '<span class="badge badge-subtle">Cached</span>' : '<span class="badge badge-success">Fresh</span>'}
          </div>
          <div class="ai-insight-section">
            <p>${escapeHtml(rem.explanation)}</p>
          </div>
          <div class="ai-patch-box">
            <pre><code>${escapeHtml(rem.code_snippet || JSON.stringify(patchProps, null, 2))}</code></pre>
          </div>
          <div style="display: flex; gap: 0.5rem; align-items: center; margin-top: 0.35rem; flex-wrap: wrap;">
            <button class="btn btn-xs btn-outline-green btn-run-rescan">
              <span>🔬 Dry-Run Rescan Verification</span>
            </button>
            <span class="rescan-result-slot"></span>
          </div>
        </div>
      `;

      const btnRescan = containerEl.querySelector('.btn-run-rescan');
      const rescanSlot = containerEl.querySelector('.rescan-result-slot');
      if (btnRescan) {
        btnRescan.addEventListener('click', (e) => {
          e.stopPropagation();
          btnRescan.disabled = true;
          btnRescan.innerHTML = `<span>⏳ Rescanning...</span>`;
          fetch(`/api/ai/remediate/${fileId}/${encodeURIComponent(findingId)}/rescan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ patch_properties: patchProps })
          })
            .then(res => res.json())
            .then(vData => {
              btnRescan.disabled = false;
              btnRescan.innerHTML = `<span>🔬 Dry-Run Rescan Verification</span>`;
              if (vData.success && vData.verification) {
                const v = vData.verification;
                if (v.resolved) {
                  rescanSlot.innerHTML = `<span class="ai-dryrun-badge badge-verified-fixed">✅ Verified: Target finding resolved!</span>`;
                } else {
                  rescanSlot.innerHTML = `<span class="ai-dryrun-badge badge-still-vulnerable">⚠️ Still vulnerable (${v.remaining_rule_violations} violation remaining)</span>`;
                }
              } else {
                rescanSlot.innerHTML = `<span style="color:#f87171; font-size:0.75rem;">Rescan check error: ${escapeHtml(vData.error || 'Unknown')}</span>`;
              }
            })
            .catch(err => {
              btnRescan.disabled = false;
              btnRescan.innerHTML = `<span>🔬 Dry-Run Rescan Verification</span>`;
              rescanSlot.innerHTML = `<span style="color:#f87171; font-size:0.75rem;">Rescan failed: ${escapeHtml(err.message)}</span>`;
            });
        });
      }
    })
    .catch(err => {
      containerEl.innerHTML = `<span style="color:#f87171;">⚠️ Network error: ${escapeHtml(err.message || String(err))}</span>`;
    });
};

