/**
 * Findings module for managing, filtering, and interacting with security audit findings.
 */
let allFindings = [];
let currentSeverityFilter = 'ALL';
let currentResourceFilter = null;

function initFindings(findingsData) {
  allFindings = findingsData || [];
  renderFindings();
  setupFindingsTabs();
}

function setupFindingsTabs() {
  const tabs = document.querySelectorAll('#findingsTabs .tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentSeverityFilter = tab.getAttribute('data-tab');
      renderFindings();
    });
  });
}

function renderFindings() {
  const container = document.getElementById('findingsListContainer');
  if (!container) return;

  container.innerHTML = '';

  const filtered = allFindings.filter(f => {
    const matchesSev = (currentSeverityFilter === 'ALL' || f.severity.toUpperCase() === currentSeverityFilter);
    const matchesRes = (!currentResourceFilter || f.affected_resource_id.toLowerCase() === currentResourceFilter.toLowerCase());
    return matchesSev && matchesRes;
  });

  const countBadge = document.getElementById('findingsCountBadge');
  if (countBadge) {
    countBadge.textContent = filtered.length;
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 2rem 1rem; color: #8b949e; font-size: 0.9rem;">
        <span>✅ No findings match the active criteria.</span>
      </div>
    `;
    return;
  }

  filtered.forEach(finding => {
    const card = document.createElement('div');
    const sevClass = getSeverityClass(finding.severity);
    card.className = `finding-card ${sevClass}`;
    card.setAttribute('data-finding-id', finding.finding_id);

    card.innerHTML = `
      <div class="finding-top">
        <div class="finding-badges">
          <span class="badge ${finding.severity.toUpperCase() === 'CRITICAL' ? 'badge-danger' : 'badge-subtle'}">${finding.severity}</span>
          <span class="badge badge-subtle">${finding.category}</span>
        </div>
        <span class="finding-rule-id">${finding.rule_id}</span>
      </div>
      <div class="finding-title">${escapeHtml(finding.title)}</div>
      <div class="finding-resource">
        <span>📍 Affected: <strong>${escapeHtml(finding.affected_resource_name)}</strong></span>
      </div>
      <div class="finding-details-collapsible">
        <div><strong>Evidence:</strong></div>
        <div class="evidence-box">${escapeHtml(finding.evidence)}</div>
        <div style="margin-top: 0.25rem;"><strong>Impact:</strong> ${escapeHtml(finding.impact)}</div>
        <div style="margin-top: 0.25rem;"><strong>Remediation:</strong></div>
        <div class="remediation-box">${escapeHtml(finding.remediation)}</div>
        <div style="font-size: 0.75rem; color: #8b949e; margin-top: 0.25rem;">
          <code>${escapeHtml(finding.json_path)}</code>
        </div>
        <div class="finding-ai-actions">
          <button class="btn btn-xs btn-outline-cyan btn-ai-explain" data-fid="${finding.finding_id}">
            <span>⚡ AI Explain</span>
          </button>
          <button class="btn btn-xs btn-outline-green btn-ai-fix" data-fid="${finding.finding_id}">
            <span>🛠️ AI Fix</span>
          </button>
        </div>
        <div class="finding-ai-container" id="aiBox_${finding.finding_id}" style="display: none;"></div>
      </div>
    `;

    const btnExplain = card.querySelector('.btn-ai-explain');
    const btnFix = card.querySelector('.btn-ai-fix');
    const aiBox = card.querySelector(`#aiBox_${finding.finding_id}`);

    if (btnExplain && aiBox) {
      btnExplain.addEventListener('click', (e) => {
        e.stopPropagation();
        if (typeof window.explainFinding === 'function') {
          window.explainFinding(finding.finding_id, aiBox);
        }
      });
    }

    if (btnFix && aiBox) {
      btnFix.addEventListener('click', (e) => {
        e.stopPropagation();
        if (typeof window.remediateFinding === 'function') {
          window.remediateFinding(finding.finding_id, aiBox);
        }
      });
    }

    card.addEventListener('click', () => {
      document.querySelectorAll('.finding-card').forEach(c => c.classList.remove('selected'));
      card.classList.add('selected');
      if (window.focusNodeById) {
        window.focusNodeById(finding.affected_resource_id);
      }
    });

    container.appendChild(card);
  });
}

function getSeverityClass(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'crit';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'med';
    case 'LOW': return 'low';
    default: return 'low';
  }
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

window.filterFindingsByResource = function(resourceId) {
  currentResourceFilter = resourceId;
  renderFindings();
};

window.resetFindingsFilter = function() {
  currentResourceFilter = null;
  renderFindings();
};

