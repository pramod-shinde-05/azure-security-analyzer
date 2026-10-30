/**
 * Main dashboard coordinator module.
 */
document.addEventListener('DOMContentLoaded', () => {
  // Safely extract bootstrapped data
  let initialData = window.INITIAL_DATA || {};
  const rawDataEl = document.getElementById('initialData');
  if (rawDataEl && rawDataEl.textContent) {
    try {
      initialData = JSON.parse(rawDataEl.textContent);
    } catch(e) {
      console.error("Error parsing embedded initialData:", e);
    }
  }

  // 1. Initialize Findings Panel First (Guaranteed execution)
  try {
    if (initialData.findings && typeof initFindings === 'function') {
      initFindings(initialData.findings);
    }
  } catch (err) {
    console.error("Error initializing findings panel:", err);
  }

  // 2. Initialize Topology Graph (Cytoscape or Native SVG)
  try {
    if (initialData.graph && typeof initCytoscapeGraph === 'function') {
      initCytoscapeGraph(initialData.graph);
    }
  } catch (err) {
    console.error("Error initializing topology graph:", err);
  }

  // 3. Toolbar actions (Works for both Cytoscape and SVG)
  const btnZoomIn = document.getElementById('btnZoomIn');
  const btnZoomOut = document.getElementById('btnZoomOut');
  const btnFit = document.getElementById('btnFit');
  const selectLayout = document.getElementById('selectLayout');

  if (btnZoomIn) {
    btnZoomIn.addEventListener('click', () => {
      if (window.cy) {
        cy.zoom(cy.zoom() * 1.25);
      } else {
        const panGroup = document.getElementById('svgPanGroup');
        if (panGroup && window.svgState) {
          svgState.zoom *= 1.2;
          panGroup.setAttribute('transform', `translate(${svgState.panX}, ${svgState.panY}) scale(${svgState.zoom})`);
        }
      }
    });
  }

  if (btnZoomOut) {
    btnZoomOut.addEventListener('click', () => {
      if (window.cy) {
        cy.zoom(cy.zoom() * 0.8);
      } else {
        const panGroup = document.getElementById('svgPanGroup');
        if (panGroup && window.svgState) {
          svgState.zoom *= 0.8;
          panGroup.setAttribute('transform', `translate(${svgState.panX}, ${svgState.panY}) scale(${svgState.zoom})`);
        }
      }
    });
  }

  if (btnFit) {
    btnFit.addEventListener('click', () => {
      if (window.cy) {
        cy.fit(null, 40);
        cy.center();
      } else {
        const panGroup = document.getElementById('svgPanGroup');
        if (panGroup && window.svgState) {
          svgState.zoom = 1;
          svgState.panX = 0;
          svgState.panY = 0;
          panGroup.setAttribute('transform', `translate(0, 0) scale(1)`);
        }
      }
    });
  }

  const btnToggleExpand = document.getElementById('btnToggleExpand');
  if (btnToggleExpand) {
    btnToggleExpand.addEventListener('click', () => {
      const workspace = document.querySelector('.workspace-grid');
      const findingsPane = document.querySelector('.findings-pane');
      if (workspace) {
        const isNowExpanded = workspace.classList.toggle('graph-fullscreen');
        if (findingsPane) {
          findingsPane.classList.toggle('pane-hidden');
        }
        btnToggleExpand.classList.toggle('active', isNowExpanded);
        btnToggleExpand.title = isNowExpanded ? "Restore Split View (Show Findings)" : "Expand Visualizer (Hide Findings)";
        btnToggleExpand.innerHTML = isNowExpanded ? `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M4 14h6v6M20 10h-6V4M14 10l7-7M3 21l7-7"></path>
          </svg>
        ` : `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"></path>
          </svg>
        `;
        setTimeout(() => {
          if (window.cy) {
            cy.resize();
            cy.fit(null, 40);
          }
        }, 150);
      }
    });
  }

  const btnToggleTraffic = document.getElementById('btnToggleTraffic');
  if (btnToggleTraffic) {
    btnToggleTraffic.addEventListener('click', () => {
      if (typeof window.toggleLiveTraffic === 'function') {
        window.toggleLiveTraffic();
      }
    });
  }

  if (selectLayout) {
    selectLayout.addEventListener('change', (e) => {
      if (typeof applyLayout === 'function') {
        applyLayout(e.target.value);
      }
    });
  }

  // 4. Node search filter
  const searchInput = document.getElementById('nodeSearchInput');
  if (searchInput) {
    searchInput.addEventListener('input', (e) => {
      const query = e.target.value.trim().toLowerCase();
      if (window.cy) {
        if (!query) {
          cy.elements().removeClass('dimmed highlighted');
          return;
        }
        cy.nodes().forEach(node => {
          const label = (node.data('label') || '').toLowerCase();
          const type = (node.data('type') || '').toLowerCase();
          if (label.includes(query) || type.includes(query)) {
            node.removeClass('dimmed').addClass('highlighted');
          } else {
            node.removeClass('highlighted').addClass('dimmed');
          }
        });
      } else {
        // SVG Search highlight
        document.querySelectorAll('.svg-node').forEach(nodeEl => {
          const text = nodeEl.textContent.toLowerCase();
          nodeEl.style.opacity = (!query || text.includes(query)) ? '1' : '0.2';
        });
      }
    });
  }

  // 5. Risk filter pills
  const riskPills = document.querySelectorAll('#riskFilterGroup .filter-pill');
  riskPills.forEach(pill => {
    pill.addEventListener('click', () => {
      riskPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      const selectedRisk = pill.getAttribute('data-risk');

      if (window.cy) {
        if (selectedRisk === 'ALL') {
          cy.elements().removeClass('dimmed highlighted');
        } else {
          cy.nodes().forEach(node => {
            const risk = (node.data('risk_level') || 'CLEAN').toUpperCase();
            if (risk === selectedRisk) {
              node.removeClass('dimmed').addClass('highlighted');
            } else {
              node.removeClass('highlighted').addClass('dimmed');
            }
          });
        }
      } else {
        // SVG Risk filter
        document.querySelectorAll('.svg-node').forEach(nodeEl => {
          const nId = nodeEl.getAttribute('data-node-id');
          const nodeData = (initialData.graph.nodes || []).find(n => n.data.id === nId);
          if (!nodeData) return;
          const risk = (nodeData.data.risk_level || 'CLEAN').toUpperCase();
          nodeEl.style.opacity = (selectedRisk === 'ALL' || risk === selectedRisk) ? '1' : '0.2';
        });
      }
    });
  });

  // 6. Close Inspector Drawer
  const btnCloseInspector = document.getElementById('btnCloseInspector');
  if (btnCloseInspector) {
    btnCloseInspector.addEventListener('click', () => {
      if (typeof closeResourceInspector === 'function') {
        closeResourceInspector();
      }
      if (typeof clearHighlights === 'function') {
        clearHighlights();
      }
    });
  }
});
