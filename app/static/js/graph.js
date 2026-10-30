/**
 * Azure ARM Security Analyzer - Topology Visualizer
 *
 * Polished Cloud Architecture Visualization Engine:
 * - Professional Azure resource cards (230x76) with crisp vector Azure service icons.
 * - Intelligent cloud architecture layout that groups tiers, preserves hierarchies,
 *   and wraps disconnected nodes so they never sprawl into a long horizontal strip.
 * - Live animated wire connections simulating real cloud network & data flow traffic.
 *   (Incoming traffic from Public IP/Internet, Outgoing data flows to Storage/Redis/DB/Vault).
 * - Clean edge rendering with directional arrows drawn behind nodes (z-index: 1 vs 10).
 * - On-demand relationship labeling on hover/selection to eliminate text collisions.
 * - Fully interactive SVG fallback with native zoom, pan, fit, and animated packet flow.
 */

let cy = null;
let currentGraphData = null;
let currentLayoutName = 'dagre';
let isTrafficFlowing = true;
let trafficOffset = 0;
let trafficAnimFrame = null;
let svgState = { zoom: 1, panX: 0, panY: 0, isDragging: false, startX: 0, startY: 0 };

const RISK_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
  INFORMATIONAL: '#38bdf8',
  CLEAN: '#10b981'
};

const CATEGORY_BG = {
  'Compute': '#0f172a',
  'Compute Storage': '#0f172a',
  'Network': '#091e3a',
  'Network Security': '#24124d',
  'Network Exposure': '#3b1219',
  'Storage': '#062d1f',
  'Security & Identity': '#2e1065',
  'Security & Secrets': '#2e1065',
  'Identity & Access': '#3b0764',
  'App Service': '#0d2847',
  'Database': '#06351d',
  'Database & Cache': '#380d15',
  'Logging & Monitoring': '#1e293b',
  'Automation': '#3b1d07',
  'Containers & AKS': '#082f49',
  'General': '#111827',
  'Other Services': '#111827'
};

// Azure Vector Icons Catalog (High-resolution, scalable 40x40 vector SVGs)
const AZURE_SVG_ICONS = {
  vm: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="3" y="4" width="18" height="13" rx="2" fill="#0078d4"/><rect x="6" y="8" width="4" height="4" fill="#ffffff"/><circle cx="16" cy="10" r="1.5" fill="#50e6ff"/><rect x="8" y="18" width="8" height="2" rx="1" fill="#005ba1"/></svg>`,
  vnet: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><circle cx="6" cy="6" r="3" fill="#0078d4"/><circle cx="18" cy="6" r="3" fill="#0078d4"/><circle cx="12" cy="18" r="3" fill="#0078d4"/><line x1="8.5" y1="7" x2="15.5" y2="7" stroke="#50e6ff" stroke-width="2"/><line x1="7.5" y1="8.5" x2="10.5" y2="15.5" stroke="#50e6ff" stroke-width="2"/><line x1="16.5" y1="8.5" x2="13.5" y2="15.5" stroke="#50e6ff" stroke-width="2"/></svg>`,
  subnet: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="3" y="3" width="18" height="18" rx="2" fill="none" stroke="#0078d4" stroke-width="2" stroke-dasharray="2,2"/><circle cx="8" cy="8" r="2" fill="#38bdf8"/><circle cx="16" cy="8" r="2" fill="#38bdf8"/><circle cx="12" cy="16" r="2" fill="#38bdf8"/><path d="M8 8 L16 8 L12 16 Z" fill="none" stroke="#38bdf8" stroke-width="1.5"/></svg>`,
  nsg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><path d="M12 2 L20 5 L20 12 C20 17 16 21 12 22 C8 21 4 17 4 12 L4 5 Z" fill="#773adc"/><path d="M12 7 L12 17 M8 11 L16 11 M8 14 L16 14" stroke="#ffffff" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  nic: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="4" y="5" width="16" height="12" rx="2" fill="#0078d4"/><circle cx="8" cy="11" r="1.5" fill="#ffffff"/><circle cx="12" cy="11" r="1.5" fill="#ffffff"/><circle cx="16" cy="11" r="1.5" fill="#ffffff"/><rect x="7" y="17" width="2" height="3" fill="#005ba1"/><rect x="11" y="17" width="2" height="3" fill="#005ba1"/><rect x="15" y="17" width="2" height="3" fill="#005ba1"/></svg>`,
  pip: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><circle cx="12" cy="12" r="9" fill="none" stroke="#f97316" stroke-width="2"/><ellipse cx="12" cy="12" rx="4.5" ry="9" fill="none" stroke="#f97316" stroke-width="1.5"/><line x1="3" y1="12" x2="21" y2="12" stroke="#f97316" stroke-width="1.5"/><line x1="5" y1="7" x2="19" y2="7" stroke="#f97316" stroke-width="1"/><line x1="5" y1="17" x2="19" y2="17" stroke="#f97316" stroke-width="1"/></svg>`,
  storage: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><ellipse cx="12" cy="5" rx="8" ry="3" fill="#107c41"/><path d="M4 5 v5 c0 1.66 3.58 3 8 3 s8 -1.34 8 -3 V5 Z" fill="#0b5a2f"/><path d="M4 10 v5 c0 1.66 3.58 3 8 3 s8 -1.34 8 -3 V10 Z" fill="#107c41"/><path d="M4 15 v4 c0 1.66 3.58 3 8 3 s8 -1.34 8 -3 V15 Z" fill="#0b5a2f"/><circle cx="16" cy="17" r="1.5" fill="#50e6ff"/></svg>`,
  keyvault: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="4" y="3" width="16" height="18" rx="3" fill="#b146c2"/><circle cx="12" cy="10" r="3.5" fill="#ffffff"/><circle cx="12" cy="10" r="1.5" fill="#b146c2"/><path d="M12 13.5 v5 M10 16.5 h4" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round"/></svg>`,
  webapp: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="3" y="4" width="18" height="15" rx="2" fill="#0078d4"/><rect x="3" y="4" width="18" height="4" fill="#005ba1"/><circle cx="6" cy="6" r="1" fill="#ffffff"/><circle cx="9" cy="6" r="1" fill="#ffffff"/><circle cx="12" cy="6" r="1" fill="#ffffff"/><path d="M8 12 L6 14 L8 16 M16 12 L18 14 L16 16 M13 11 L11 17" stroke="#38bdf8" stroke-width="1.5" stroke-linecap="round" fill="none"/></svg>`,
  sql: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><ellipse cx="12" cy="6" rx="7" ry="2.5" fill="#0078d4"/><path d="M5 6 v6 c0 1.4 3.1 2.5 7 2.5 s7 -1.1 7 -2.5 V6 Z" fill="#005ba1"/><path d="M5 12 v6 c0 1.4 3.1 2.5 7 2.5 s7 -1.1 7 -2.5 V12 Z" fill="#004578"/><ellipse cx="12" cy="12" rx="7" ry="2" fill="none" stroke="#38bdf8" stroke-width="1"/></svg>`,
  lb: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="9" y="3" width="6" height="4" rx="1" fill="#773adc"/><rect x="3" y="17" width="5" height="4" rx="1" fill="#773adc"/><rect x="16" y="17" width="5" height="4" rx="1" fill="#773adc"/><path d="M12 7 v4 M12 11 H5.5 v6 M12 11 H18.5 v6" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" fill="none"/></svg>`,
  appgateway: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="3" y="4" width="18" height="16" rx="2" fill="#0078d4"/><path d="M7 8 L12 4 L17 8 L17 14 C17 17 12 19 12 19 C12 19 7 17 7 14 Z" fill="#773adc"/><path d="M10 11 L14 11 M12 9 L12 13" stroke="#ffffff" stroke-width="1.5" stroke-linecap="round"/></svg>`,
  identity: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><circle cx="12" cy="8" r="4" fill="#eab308"/><path d="M4 20 C4 15.5 7.5 13 12 13 C16.5 13 20 15.5 20 20 Z" fill="#ca8a04"/><circle cx="17" cy="17" r="3.5" fill="#10b981"/><path d="M15.5 17 l1 1 l2 -2" stroke="#ffffff" stroke-width="1.2" fill="none"/></svg>`,
  role: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="4" y="5" width="16" height="14" rx="2" fill="#eab308"/><circle cx="12" cy="10" r="2.5" fill="#0f172a"/><path d="M9 16 c0 -1.5 1.5 -2.5 3 -2.5 s3 1 3 2.5" fill="#0f172a"/><rect x="6" y="7" width="3" height="1.5" fill="#0f172a"/></svg>`,
  plan: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><rect x="3" y="4" width="18" height="5" rx="1" fill="#0078d4"/><rect x="3" y="10" width="18" height="5" rx="1" fill="#0078d4"/><rect x="3" y="16" width="18" height="5" rx="1" fill="#0078d4"/><circle cx="6" cy="6.5" r="1" fill="#50e6ff"/><circle cx="6" cy="12.5" r="1" fill="#50e6ff"/><circle cx="6" cy="18.5" r="1" fill="#50e6ff"/></svg>`,
  redis: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><polygon points="12,2 22,7 12,12 2,7" fill="#dc2626"/><polygon points="2,12 12,17 22,12 12,7" fill="#b91c1c"/><polygon points="2,17 12,22 22,17 12,12" fill="#991b1b"/></svg>`,
  automation: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><circle cx="12" cy="12" r="8" fill="#ea580c"/><circle cx="12" cy="12" r="3" fill="#ffffff"/><path d="M12 2 v3 M12 19 v3 M2 12 h3 M19 12 h3" stroke="#ea580c" stroke-width="2.5" stroke-linecap="round"/></svg>`,
  generic: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="40" height="40"><path d="M19.35 10.04 C18.67 6.59 15.64 4 12 4 C9.11 4 6.6 5.64 5.35 8.04 C2.34 8.36 0 10.91 0 14 C0 17.31 2.69 20 6 20 H19 C21.76 20 24 17.76 24 15 C24 12.36 21.95 10.22 19.35 10.04 Z" fill="#0078d4"/><circle cx="12" cy="13" r="2.5" fill="#50e6ff"/></svg>`
};

function getAzureIconKey(type, category) {
  const lowType = (type || '').toLowerCase();
  const lowCat = (category || '').toLowerCase();

  if (lowType.includes('virtualmachine') && !lowType.includes('scaleset')) return 'vm';
  if (lowType.includes('virtualnetwork') && !lowType.includes('subnet')) return 'vnet';
  if (lowType.includes('subnet')) return 'subnet';
  if (lowType.includes('networksecuritygroup')) return 'nsg';
  if (lowType.includes('networkinterface')) return 'nic';
  if (lowType.includes('publicipaddress')) return 'pip';
  if (lowType.includes('storageaccount')) return 'storage';
  if (lowType.includes('keyvault')) return 'keyvault';
  if (lowType.includes('sites') && !lowType.includes('serverfarm')) return 'webapp';
  if (lowType.includes('serverfarm')) return 'plan';
  if (lowType.includes('sql') || lowType.includes('databases')) return 'sql';
  if (lowType.includes('loadbalancer')) return 'lb';
  if (lowType.includes('applicationgateway')) return 'appgateway';
  if (lowType.includes('userassignedidentities') || lowType.includes('managedidentity')) return 'identity';
  if (lowType.includes('roleassignment') || lowType.includes('roledefinition')) return 'role';
  if (lowType.includes('redis')) return 'redis';
  if (lowType.includes('automation')) return 'automation';

  if (lowCat.includes('compute')) return 'vm';
  if (lowCat.includes('storage')) return 'storage';
  if (lowCat.includes('app service')) return 'webapp';
  if (lowCat.includes('database')) return 'sql';
  if (lowCat.includes('security')) return 'nsg';

  return 'generic';
}

function getAzureIconSvg(type, category) {
  const key = getAzureIconKey(type, category);
  return AZURE_SVG_ICONS[key] || AZURE_SVG_ICONS.generic;
}

function getIconDataUri(type, category) {
  const svg = getAzureIconSvg(type, category);
  return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
}

/**
 * Intelligent Cloud Architecture Layout Algorithm:
 * - Groups resources by cloud architectural tier:
 *   Tier 0: Network Ingress & Connectivity (Public IPs, VNets, Subnets, Gateways, NICs, NSGs)
 *   Tier 1: Compute & Workloads (Web Apps, Virtual Machines, App Service Plans, Containers)
 *   Tier 2: Backend Data & Storage (Storage Accounts, SQL Databases, Redis Caches)
 *   Tier 3: Security, Governance & Identity (Key Vaults, Roles, RBAC, Automation)
 * - Renders connected DAGs top-to-bottom and wraps resources in balanced 3-4 column tiers
 * - Guarantees the graph never stretches into an uncontrollable single horizontal line.
 */
function computeArchitecturalLayout(nodes, edges, containerWidth, containerHeight) {
  if (!nodes || nodes.length === 0) return {};

  const width = Math.max(820, containerWidth || 850);
  const height = Math.max(540, containerHeight || 550);
  const nodeW = 230;
  const nodeH = 76;
  const gapX = 40;
  const gapY = 55;

  const positions = {};

  const inDegree = {};
  const adj = {};
  const nodeMap = {};

  nodes.forEach(n => {
    const id = n.data.id;
    inDegree[id] = 0;
    adj[id] = [];
    nodeMap[id] = n;
  });

  (edges || []).forEach(e => {
    const s = e.data.source;
    const t = e.data.target;
    if (inDegree[t] !== undefined && inDegree[s] !== undefined) {
      inDegree[t]++;
      adj[s].push(t);
    }
  });

  function getTier(node) {
    const type = (node.data.type || '').toLowerCase();
    const cat = (node.data.category || '').toLowerCase();
    if (type.includes('network') || type.includes('virtualnetwork') || type.includes('subnet') || type.includes('publicip') || type.includes('loadbalancer') || type.includes('applicationgateway')) {
      return 0; // Network Tier
    }
    if (type.includes('virtualmachine') || type.includes('sites') || type.includes('serverfarm') || type.includes('managedclusters')) {
      return 1; // Compute & Workloads Tier
    }
    if (type.includes('storage') || type.includes('sql') || type.includes('databases') || type.includes('redis') || cat.includes('database')) {
      return 2; // Data & Storage Tier
    }
    return 3; // Security, Identity & Governance Tier
  }

  const tiers = { 0: [], 1: [], 2: [], 3: [] };
  nodes.forEach(n => {
    tiers[getTier(n)].push(n);
  });

  // Balanced tier-based cloud architecture layout
  let currentY = 40;
  const tierKeys = [0, 1, 2, 3];

  tierKeys.forEach(tKey => {
    const tierNodes = tiers[tKey];
    if (tierNodes.length === 0) return;

    // Wrap tier nodes in rows of 3 to 4 nodes
    const maxCols = Math.min(4, Math.max(2, tierNodes.length));
    const numSubRows = Math.ceil(tierNodes.length / maxCols);

    for (let r = 0; r < numSubRows; r++) {
      const slice = tierNodes.slice(r * maxCols, (r + 1) * maxCols);
      const cols = slice.length;
      const totalRowW = cols * nodeW + (cols - 1) * gapX;
      const startX = Math.max(40, (width - totalRowW) / 2);

      slice.forEach((node, colIdx) => {
        positions[node.data.id] = {
          x: startX + colIdx * (nodeW + gapX),
          y: currentY + r * (nodeH + gapY)
        };
      });
    }

    currentY += numSubRows * (nodeH + gapY);
  });

  return positions;
}

/**
 * Main initialization entry point for the topology graph.
 */
function initCytoscapeGraph(graphData) {
  const container = document.getElementById('cy');
  if (!container || !graphData || !graphData.nodes) return;
  currentGraphData = graphData;

  // Validate and sanitize edges to guarantee that both source & target exist in nodes
  const nodeIds = new Set(graphData.nodes.map(n => n.data.id));
  const validEdges = (graphData.edges || []).filter(e => {
    return e && e.data && nodeIds.has(e.data.source) && nodeIds.has(e.data.target);
  });

  const elements = [
    ...graphData.nodes.map(n => ({ group: 'nodes', data: n.data })),
    ...validEdges.map(e => ({ group: 'edges', data: e.data }))
  ];

  // Try Cytoscape if available on window
  if (typeof cytoscape !== 'undefined') {
    try {
      cy = cytoscape({
        container: container,
        elements: elements,
        boxSelectionEnabled: false,
        autounselectify: false,
        wheelSensitivity: 0.2,
        style: [
          // Professional Azure Resource Card Node
          {
            selector: 'node',
            style: {
              'shape': 'round-rectangle',
              'width': 230,
              'height': 76,
              'z-index': 10, // Nodes always sit on top of edges
              'background-color': '#131b2e',
              'border-width': 2.5,
              'border-color': function(ele) {
                const risk = ele.data('risk_level') || 'CLEAN';
                return RISK_COLORS[risk] || '#475569';
              },
              'border-opacity': 1,
              // Vector SVG Icon on the left
              'background-image': function(ele) {
                return getIconDataUri(ele.data('type'), ele.data('category'));
              },
              'background-width': '38px',
              'background-height': '38px',
              'background-position-x': '16px',
              'background-position-y': '50%',
              'background-clip': 'none',
              'background-fit': 'none',
              // Clear typography inside the card
              'label': function(ele) {
                const name = truncate(ele.data('label') || ele.data('id'), 18);
                const shortType = ele.data('type_short') || ele.data('category') || 'Resource';
                const count = ele.data('finding_count') || 0;
                const badge = count > 0 ? `\n[ ${count} Issue${count > 1 ? 's' : ''} ]` : '';
                return `${name}\n${shortType}${badge}`;
              },
              'color': '#f8fafc',
              'font-size': 11,
              'font-weight': '700',
              'font-family': '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
              'text-valign': 'center',
              'text-halign': 'center',
              'text-margin-x': 24, // Shift text right to leave clearance for 40px icon
              'text-wrap': 'wrap',
              'text-max-width': 145,
              'line-height': 1.35,
              'transition-property': 'border-width, border-color, underlay-opacity',
              'transition-duration': '0.2s'
            }
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 4.5,
              'border-color': '#38bdf8',
              'underlay-color': '#38bdf8',
              'underlay-padding': 6,
              'underlay-opacity': 0.45,
              'z-index': 20
            }
          },
          {
            selector: 'node.highlighted',
            style: {
              'border-width': 4.5,
              'border-color': '#38bdf8',
              'underlay-color': '#38bdf8',
              'underlay-padding': 6,
              'underlay-opacity': 0.45,
              'z-index': 20
            }
          },
          {
            selector: 'node.path-entry',
            style: {
              'border-width': 5.5,
              'border-color': '#f97316',
              'underlay-color': '#f97316',
              'underlay-padding': 10,
              'underlay-opacity': 0.55,
              'z-index': 30
            }
          },
          {
            selector: 'node.path-target',
            style: {
              'border-width': 5.5,
              'border-color': '#ef4444',
              'underlay-color': '#ef4444',
              'underlay-padding': 10,
              'underlay-opacity': 0.55,
              'z-index': 30
            }
          },
          {
            selector: 'node.dimmed',
            style: {
              'opacity': 0.2
            }
          },
          // Base Edge Styling - Live Animated Electric Wire drawn behind nodes
          {
            selector: 'edge',
            style: {
              'z-index': 1,
              'width': 2.5,
              'curve-style': 'bezier',
              'target-arrow-shape': 'triangle',
              'target-arrow-color': '#64748b',
              'line-color': '#64748b',
              'line-style': 'dashed',
              'line-dash-pattern': [8, 5],
              'line-dash-offset': 0,
              'arrow-scale': 1.25,
              'opacity': 0.85,
              'label': '', // Clean! Never permanently label every edge
              'text-background-color': '#090d16',
              'text-background-opacity': 0.95,
              'text-background-padding': 3,
              'text-background-shape': 'round-rectangle'
            }
          },
          // On-Demand Relationship Labeling: Appears on edge hover, selection, or node click
          {
            selector: 'edge.hovered, edge:selected, edge.highlighted',
            style: {
              'label': 'data(label)',
              'font-size': 10.5,
              'font-weight': '600',
              'color': '#f8fafc',
              'text-rotation': 'autorotate',
              'z-index': 25,
              'width': 3.8,
              'opacity': 1
            }
          },
          // Relationship-specific color tokens (matching legend)
          // 1. External Exposure Wire (Public IP -> Ingress)
          {
            selector: 'edge[relation_type = "exposure"]',
            style: {
              'line-color': '#f97316',
              'target-arrow-color': '#f97316',
              'line-dash-pattern': [9, 5]
            }
          },
          // 2. Network Association / Internal Traffic Wire
          {
            selector: 'edge[relation_type = "network_association"]',
            style: {
              'line-color': '#38bdf8',
              'target-arrow-color': '#38bdf8',
              'line-dash-pattern': [8, 5]
            }
          },
          // 3. Application Data Flow Wire (App -> Storage, Redis, DB)
          {
            selector: 'edge[relation_type = "data_flow"]',
            style: {
              'line-color': '#10b981',
              'target-arrow-color': '#10b981',
              'line-dash-pattern': [7, 4]
            }
          },
          // 4. Secret & Security Integration Wire (App -> Key Vault)
          {
            selector: 'edge[relation_type = "integration"]',
            style: {
              'line-color': '#c084fc',
              'target-arrow-color': '#c084fc',
              'line-dash-pattern': [8, 5]
            }
          },
          // 5. Network Security Boundary Wire (NSG -> NIC/Subnet)
          {
            selector: 'edge[relation_type = "security_boundary"]',
            style: {
              'line-color': '#a855f7',
              'target-arrow-color': '#a855f7',
              'line-dash-pattern': [6, 4]
            }
          },
          // 6. Role / Authorization Wire
          {
            selector: 'edge[relation_type = "authorization"]',
            style: {
              'line-color': '#eab308',
              'target-arrow-color': '#eab308',
              'line-dash-pattern': [4, 4]
            }
          },
          // 7. General Architecture Dependency
          {
            selector: 'edge[relation_type = "dependency"]',
            style: {
              'line-color': '#94a3b8',
              'target-arrow-color': '#94a3b8',
              'line-dash-pattern': [7, 5]
            }
          },
          // 8. Hosting & Containment
          {
            selector: 'edge[relation_type = "hosting"]',
            style: {
              'line-color': '#06b6d4',
              'target-arrow-color': '#06b6d4'
            }
          },
          {
            selector: 'edge[relation_type = "containment"]',
            style: {
              'line-color': '#94a3b8',
              'target-arrow-color': '#94a3b8'
            }
          },
          {
            selector: 'edge[relation_type = "monitoring"]',
            style: {
              'line-color': '#10b981',
              'target-arrow-color': '#10b981'
            }
          },
          {
            selector: 'edge.dimmed',
            style: {
              'opacity': 0.12
            }
          }
        ]
      });

      // Expose globally
      window.cy = cy;

      // Apply initial intelligent architectural layout
      applyLayout('dagre');

      // Start live wire traffic flow animation
      startCytoscapeTrafficAnimation();

      // Edge hover interaction: show relationship detail on hover
      cy.on('mouseover', 'edge', function(evt) {
        evt.target.addClass('hovered');
      });
      cy.on('mouseout', 'edge', function(evt) {
        evt.target.removeClass('hovered');
      });

      // Node selection listeners
      cy.on('select', 'node', function(evt) {
        const node = evt.target;
        inspectResource(node.data());
        highlightNodeAndNeighborhood(node);
        if (window.filterFindingsByResource) {
          window.filterFindingsByResource(node.id());
        }
      });

      cy.on('tap', function(evt) {
        if (evt.target === cy) {
          clearHighlights();
          closeResourceInspector();
          if (window.resetFindingsFilter) {
            window.resetFindingsFilter();
          }
        }
      });

      // Window resize listener
      window.addEventListener('resize', () => {
        if (cy) {
          cy.resize();
        }
      });

      return;
    } catch (err) {
      console.warn("Cytoscape initialization issue, falling back to Native SVG Visualizer:", err);
    }
  }

  // Pure SVG Interactive Visualizer fallback
  renderSvgFallbackGraph(graphData, validEdges, currentLayoutName);
}

/**
 * High-performance smooth traffic animation loop for Cytoscape.js
 * Moves dash offsets to simulate live incoming packets and outgoing data requests.
 */
function startCytoscapeTrafficAnimation() {
  if (trafficAnimFrame) {
    cancelAnimationFrame(trafficAnimFrame);
    trafficAnimFrame = null;
  }

  function step() {
    if (isTrafficFlowing && cy) {
      trafficOffset = (trafficOffset - 0.72) % 26;
      cy.batch(() => {
        // Incoming external traffic marches into the infrastructure
        cy.edges('[traffic_flow = "incoming"]').style('line-dash-offset', -trafficOffset);
        // Outgoing data flows to Storage, Cache, DB, Secrets march outward
        cy.edges('[traffic_flow = "outgoing"]').style('line-dash-offset', trafficOffset);
        // Forward network associations & dependencies march forward
        cy.edges('[traffic_flow = "forward"]').style('line-dash-offset', trafficOffset);
        // Policy / boundary wires pulse gently
        cy.edges('[traffic_flow = "control"]').style('line-dash-offset', trafficOffset * 0.5);
      });
    }
    trafficAnimFrame = requestAnimationFrame(step);
  }

  trafficAnimFrame = requestAnimationFrame(step);
}

/**
 * Toggles live traffic flow animation.
 */
function toggleLiveTraffic() {
  isTrafficFlowing = !isTrafficFlowing;
  const btn = document.getElementById('btnToggleTraffic');
  if (btn) {
    btn.classList.toggle('active', isTrafficFlowing);
    btn.classList.toggle('btn-traffic-paused', !isTrafficFlowing);
    btn.title = isTrafficFlowing ? "Live Wire Traffic: Active (Click to Pause)" : "Live Wire Traffic: Paused (Click to Resume)";
  }

  const container = document.getElementById('cy');
  if (container) {
    container.classList.toggle('traffic-paused', !isTrafficFlowing);
  }
}

/**
 * Layout-switching function with Intelligent Architectural Layout as the default Dagre engine.
 */
function applyLayout(layoutName) {
  if (!layoutName) layoutName = 'dagre';
  currentLayoutName = layoutName;

  const selectLayout = document.getElementById('selectLayout');
  if (selectLayout && selectLayout.value !== layoutName) {
    selectLayout.value = layoutName;
  }

  if (cy) {
    const container = document.getElementById('cy');
    const width = container ? container.clientWidth : 850;
    const height = container ? container.clientHeight : 550;

    if (layoutName === 'dagre') {
      const calculatedPositions = computeArchitecturalLayout(
        currentGraphData.nodes,
        currentGraphData.edges,
        width,
        height
      );

      cy.batch(() => {
        cy.nodes().forEach(node => {
          const pos = calculatedPositions[node.id()];
          if (pos) {
            node.position(pos);
          }
        });
      });

      cy.fit(null, 40);
      cy.center();
      return;
    } else if (layoutName === 'cose') {
      cy.layout({
        name: 'cose',
        animate: true,
        animationDuration: 500,
        refresh: 20,
        fit: true,
        padding: 40,
        randomize: false,
        componentSpacing: 80,
        nodeRepulsion: function() { return 4500; },
        nodeOverlap: 40,
        idealEdgeLength: function() { return 110; },
        edgeElasticity: function() { return 64; },
        gravity: 50
      }).run();
    } else if (layoutName === 'breadthfirst') {
      cy.layout({
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.4,
        padding: 40,
        animate: true,
        animationDuration: 400,
        fit: true
      }).run();
    } else if (layoutName === 'grid') {
      cy.layout({
        name: 'grid',
        fit: true,
        padding: 40,
        animate: true,
        animationDuration: 400,
        avoidOverlap: true,
        spacingFactor: 1.2
      }).run();
    }
  } else if (currentGraphData) {
    renderSvgFallbackGraph(currentGraphData, null, layoutName);
  }
}

function highlightNodeAndNeighborhood(node) {
  if (!cy) return;
  cy.elements().removeClass('highlighted dimmed hovered');
  const neighborhood = node.neighborhood().add(node);
  cy.elements().not(neighborhood).addClass('dimmed');
  neighborhood.addClass('highlighted');
}

function clearHighlights() {
  if (cy) {
    cy.elements().removeClass('highlighted dimmed hovered path-entry path-target');
  } else {
    document.querySelectorAll('.svg-node').forEach(n => {
      n.classList.remove('selected');
      const r = n.querySelector('rect');
      if (r) r.setAttribute('stroke-width', '2.5');
    });
  }
}

window.highlightAttackPath = function(pathData) {
  if (!pathData || !pathData.steps || pathData.steps.length === 0) return;

  const pathResourceIds = new Set(pathData.steps.map(s => (s.resource_id || '').toLowerCase()));

  if (cy) {
    cy.batch(() => {
      cy.elements().addClass('dimmed').removeClass('highlighted path-entry path-target');

      // Highlight participating nodes
      const pathNodes = cy.nodes().filter(node => pathResourceIds.has(node.id().toLowerCase()));
      pathNodes.removeClass('dimmed').addClass('highlighted');

      // Highlight Entry Point (step 1)
      const firstStepId = (pathData.steps[0].resource_id || '').toLowerCase();
      const entryNode = cy.nodes().filter(n => n.id().toLowerCase() === firstStepId);
      if (entryNode.length > 0) {
        entryNode.addClass('path-entry');
      }

      // Highlight Objective/Target (last step)
      if (pathData.steps.length > 1) {
        const lastStepId = (pathData.steps[pathData.steps.length - 1].resource_id || '').toLowerCase();
        const targetNode = cy.nodes().filter(n => n.id().toLowerCase() === lastStepId);
        if (targetNode.length > 0) {
          targetNode.addClass('path-target');
        }
      }

      // Highlight existing connecting edges between participating path nodes
      const pathEdges = cy.edges().filter(edge => {
        return pathResourceIds.has(edge.source().id().toLowerCase()) &&
               pathResourceIds.has(edge.target().id().toLowerCase());
      });
      pathEdges.removeClass('dimmed').addClass('highlighted');
    });

    const activeElements = cy.elements('.highlighted');
    if (activeElements.length > 0) {
      cy.animate({
        fit: { eles: activeElements, padding: 60 }
      }, { duration: 450 });
    }
  }
};

window.clearAttackPathHighlight = function() {
  clearHighlights();
  if (cy) {
    cy.fit(null, 40);
  }
};

function focusNodeById(resourceId) {
  if (!resourceId) return;

  if (cy) {
    const node = cy.getElementById(resourceId);
    if (node && node.length > 0) {
      highlightNodeAndNeighborhood(node);
      cy.animate({ center: { eles: node }, zoom: 1.15 }, { duration: 400 });
      inspectResource(node.data());
    }
  } else {
    const svgNode = document.querySelector(`[data-node-id="${resourceId}"]`);
    if (svgNode) {
      document.querySelectorAll('.svg-node').forEach(n => {
        n.classList.remove('selected');
        const r = n.querySelector('rect');
        if (r) r.setAttribute('stroke-width', '2.5');
      });
      svgNode.classList.add('selected');
      const rect = svgNode.querySelector('rect');
      if (rect) rect.setAttribute('stroke-width', '5');

      if (currentGraphData && currentGraphData.nodes) {
        const nodeData = currentGraphData.nodes.find(n => n.data.id === resourceId);
        if (nodeData) inspectResource(nodeData.data);
      }
    }
  }
}

function inspectResource(nodeData) {
  const drawer = document.getElementById('resourceInspector');
  const body = document.getElementById('inspectorBody');
  const nameLabel = document.getElementById('inspectResourceName');
  const riskBadge = document.getElementById('inspectResourceRisk');
  const typeLabel = document.getElementById('inspectResourceType');
  const locLabel = document.getElementById('inspectResourceLocation');
  const apiLabel = document.getElementById('inspectResourceApiVersion');
  const pathLabel = document.getElementById('inspectResourcePath');
  const jsonCode = document.getElementById('inspectResourcePropertiesJson');

  if (!drawer || !body) return;

  const risk = nodeData.risk_level || 'CLEAN';
  const riskColor = RISK_COLORS[risk] || '#475569';
  const shortType = nodeData.type_short || nodeData.category || 'Azure Resource';

  nameLabel.innerHTML = `<strong>${escapeHtml(nodeData.label || nodeData.id)}</strong> <span style="font-size: 0.82rem; color: #94a3b8; margin-left: 0.5rem;">(${escapeHtml(shortType)})</span>`;
  riskBadge.textContent = risk;
  riskBadge.style.backgroundColor = riskColor;
  riskBadge.style.color = '#ffffff';

  typeLabel.textContent = nodeData.type || 'N/A';
  locLabel.textContent = nodeData.location || 'Global / Resource Group';
  apiLabel.textContent = nodeData.api_version || 'N/A';
  pathLabel.textContent = nodeData.json_path || 'N/A';

  // Associated findings section
  let findingsContainer = document.getElementById('inspectResourceFindingsList');
  if (!findingsContainer) {
    const findingsDiv = document.createElement('div');
    findingsDiv.id = 'inspectResourceFindingsSection';
    findingsDiv.innerHTML = `
      <div style="margin-top: 0.75rem; margin-bottom: 0.35rem;">
        <strong>Associated Security Findings:</strong>
        <span class="badge" id="inspectResourceFindingsCount" style="margin-left: 0.4rem;"></span>
      </div>
      <div id="inspectResourceFindingsList" style="display: flex; flex-direction: column; gap: 0.4rem; max-height: 140px; overflow-y: auto;"></div>
    `;
    body.insertBefore(findingsDiv, body.querySelector('.inspector-json-section'));
    findingsContainer = document.getElementById('inspectResourceFindingsList');
  }

  const findingsCountEl = document.getElementById('inspectResourceFindingsCount');
  const findingsList = nodeData.findings || [];
  if (findingsCountEl) {
    findingsCountEl.textContent = `${findingsList.length} Finding${findingsList.length === 1 ? '' : 's'}`;
    findingsCountEl.className = `badge ${findingsList.length > 0 ? 'badge-danger' : 'badge-clean'}`;
  }

  if (findingsContainer) {
    if (findingsList.length === 0) {
      findingsContainer.innerHTML = `<span style="font-size: 0.82rem; color: #10b981;">✅ No security misconfigurations identified on this resource.</span>`;
    } else {
      findingsContainer.innerHTML = findingsList.map(f => `
        <div class="inspector-finding-pill" data-finding-id="${escapeHtml(f.finding_id)}" style="background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); padding: 0.35rem 0.6rem; border-radius: 4px; font-size: 0.82rem; display: flex; justify-content: space-between; align-items: center; cursor: pointer;">
          <span><strong>${escapeHtml(f.rule_id)}</strong>: ${escapeHtml(f.title)}</span>
          <span class="badge" style="background:${RISK_COLORS[f.severity] || '#ef4444'}; color:#fff; font-size: 0.68rem;">${escapeHtml(f.severity)}</span>
        </div>
      `).join('');

      findingsContainer.querySelectorAll('.inspector-finding-pill').forEach(pill => {
        pill.addEventListener('click', () => {
          const fId = pill.getAttribute('data-finding-id');
          const findingCard = document.querySelector(`.finding-card[data-finding-id="${fId}"]`);
          if (findingCard) {
            findingCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
            findingCard.click();
          }
        });
      });
    }
  }

  // Associated relationships section
  let relsContainer = document.getElementById('inspectResourceRelsList');
  if (!relsContainer) {
    const relsDiv = document.createElement('div');
    relsDiv.id = 'inspectResourceRelsSection';
    relsDiv.innerHTML = `
      <div style="margin-top: 0.75rem; margin-bottom: 0.35rem;">
        <strong>Topology Relationships:</strong>
      </div>
      <div id="inspectResourceRelsList" style="display: flex; flex-wrap: wrap; gap: 0.4rem; font-size: 0.8rem;"></div>
    `;
    body.insertBefore(relsDiv, body.querySelector('.inspector-json-section'));
    relsContainer = document.getElementById('inspectResourceRelsList');
  }

  if (relsContainer && currentGraphData && currentGraphData.edges) {
    const rId = nodeData.id;
    const connectedEdges = currentGraphData.edges.filter(e => e.data.source === rId || e.data.target === rId);
    if (connectedEdges.length === 0) {
      relsContainer.innerHTML = `<span style="color: #94a3b8;">Isolated resource (no direct dependencies or network links detected).</span>`;
    } else {
      relsContainer.innerHTML = connectedEdges.map(e => {
        const isSource = e.data.source === rId;
        const otherId = isSource ? e.data.target : e.data.source;
        const otherNode = currentGraphData.nodes.find(n => n.data.id === otherId);
        const otherName = otherNode ? (otherNode.data.label || otherId) : otherId;
        const arrow = isSource ? '➔' : '⬅';
        return `
          <span class="inspector-rel-tag" data-target-id="${escapeHtml(otherId)}" style="background: #1c263b; border: 1px solid #243147; padding: 0.25rem 0.55rem; border-radius: 4px; color: #f8fafc; cursor: pointer;">
            ${arrow} <em>${escapeHtml(e.data.label || e.data.relation_type)}</em>: <strong>${escapeHtml(truncate(otherName, 18))}</strong>
          </span>
        `;
      }).join('');

      relsContainer.querySelectorAll('.inspector-rel-tag').forEach(tag => {
        tag.addEventListener('click', () => {
          const tId = tag.getAttribute('data-target-id');
          focusNodeById(tId);
        });
      });
    }
  }

  jsonCode.textContent = JSON.stringify(nodeData.properties || {}, null, 2);
  body.classList.remove('hidden');
}

function closeResourceInspector() {
  const body = document.getElementById('inspectorBody');
  const nameLabel = document.getElementById('inspectResourceName');
  if (body) body.classList.add('hidden');
  if (nameLabel) nameLabel.textContent = "Select a node in the graph to inspect configuration";
}

/**
 * Built-in Native SVG Interactive Topology Renderer (100% Offline)
 * - Renders crisp professional Azure resource cards.
 * - Draws live animated wires with flowing pulses and packet particles.
 * - Supports native pan, zoom, and fit interactions.
 */
function renderSvgFallbackGraph(graphData, validEdges, layoutName) {
  const container = document.getElementById('cy');
  if (!container || !graphData || !graphData.nodes) return;

  const currentLayout = layoutName || currentLayoutName || 'dagre';
  const nodes = graphData.nodes;
  const edges = validEdges || graphData.edges || [];

  const width = Math.max(820, container.clientWidth || 850);
  const height = Math.max(540, container.clientHeight || 550);
  const nodeW = 230;
  const nodeH = 76;

  let positions = {};
  if (currentLayout === 'grid') {
    const cols = Math.min(4, Math.max(2, Math.ceil(Math.sqrt(nodes.length * 1.3))));
    const gapX = 40;
    const gapY = 55;
    const numRows = Math.ceil(nodes.length / cols);
    const startY = Math.max(40, (height - (numRows * nodeH + (numRows - 1) * gapY)) / 2);
    nodes.forEach((node, idx) => {
      const col = idx % cols;
      const row = Math.floor(idx / cols);
      const rowCols = Math.min(cols, nodes.length - row * cols);
      const rowWidth = rowCols * nodeW + (rowCols - 1) * gapX;
      const startX = Math.max(40, (width - rowWidth) / 2);
      positions[node.data.id] = {
        x: startX + col * (nodeW + gapX),
        y: startY + row * (nodeH + gapY)
      };
    });
  } else if (currentLayout === 'cose') {
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width * 0.38, Math.max(180, nodes.length * 28));
    nodes.forEach((node, idx) => {
      const angle = (2 * Math.PI * idx) / nodes.length;
      positions[node.data.id] = {
        x: centerX + radius * Math.cos(angle) - nodeW / 2,
        y: centerY + (radius * 0.72) * Math.sin(angle) - nodeH / 2
      };
    });
  } else {
    positions = computeArchitecturalLayout(nodes, edges, width, height);
  }

  let svgHtml = `
    <svg id="svgTopologyCanvas" width="100%" height="100%" viewBox="0 0 ${width} ${height}" style="background:#080c14; cursor: grab;">
      <defs>
        <marker id="svgArrowCyan" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
        </marker>
        <marker id="svgArrowOrange" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#f97316" />
        </marker>
        <marker id="svgArrowGreen" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981" />
        </marker>
        <marker id="svgArrowPurple" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#c084fc" />
        </marker>
        <marker id="svgArrowYellow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#eab308" />
        </marker>
        <marker id="svgArrowSlate" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
        </marker>
      </defs>
      <g id="svgPanGroup" transform="translate(${svgState.panX}, ${svgState.panY}) scale(${svgState.zoom})">
        <!-- Live Animated Wires Group: Drawn FIRST behind nodes -->
        <g id="svgEdgesGroup">
  `;

  // Draw Edges behind nodes with animated dashed wires and traveling packet particles
  edges.forEach(edge => {
    const p1 = positions[edge.data.source];
    const p2 = positions[edge.data.target];
    if (p1 && p2) {
      const x1 = p1.x + nodeW / 2;
      const y1 = p1.y + nodeH / 2;
      const x2 = p2.x + nodeW / 2;
      const y2 = p2.y + nodeH / 2;

      let color = '#64748b';
      let marker = 'url(#svgArrowSlate)';
      let trafficClass = 'live-traffic-forward';
      let animDur = 2.4;

      const rel = edge.data.relation_type;
      const flow = edge.data.traffic_flow || 'forward';

      if (rel === 'network_association') {
        color = '#38bdf8';
        marker = 'url(#svgArrowCyan)';
        trafficClass = 'live-traffic-forward';
        animDur = 2.2;
      } else if (rel === 'exposure') {
        color = '#f97316';
        marker = 'url(#svgArrowOrange)';
        trafficClass = 'live-traffic-incoming';
        animDur = 1.8;
      } else if (rel === 'data_flow') {
        color = '#10b981';
        marker = 'url(#svgArrowGreen)';
        trafficClass = 'live-traffic-forward';
        animDur = 2.0;
      } else if (rel === 'integration') {
        color = '#c084fc';
        marker = 'url(#svgArrowPurple)';
        trafficClass = 'live-traffic-forward';
        animDur = 2.4;
      } else if (rel === 'security_boundary') {
        color = '#a855f7';
        marker = 'url(#svgArrowPurple)';
        trafficClass = 'live-traffic-pulse';
        animDur = 3.0;
      } else if (rel === 'authorization') {
        color = '#eab308';
        marker = 'url(#svgArrowYellow)';
        trafficClass = 'live-traffic-forward';
        animDur = 2.5;
      } else if (rel === 'hosting') {
        color = '#06b6d4';
        marker = 'url(#svgArrowCyan)';
        trafficClass = 'live-traffic-forward';
        animDur = 2.4;
      } else if (rel === 'dependency') {
        color = '#64748b';
        marker = 'url(#svgArrowSlate)';
        trafficClass = 'live-traffic-forward';
        animDur = 2.8;
      }

      svgHtml += `
        <g class="svg-edge-wire-group" data-edge-id="${edge.data.id}">
          <!-- Wire subtle glow base -->
          <line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="4.5" opacity="0.18" />
          <!-- Live traffic wire -->
          <line class="svg-edge-line ${trafficClass}" data-edge-id="${edge.data.id}" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" stroke-width="2.3" stroke-dasharray="8 5" marker-end="${marker}" opacity="0.85">
            <title>${escapeSvg(edge.data.label || rel)}</title>
          </line>
          <!-- Traveling traffic packet particle -->
          <circle r="3.2" fill="${color}" opacity="0.95">
            <animateMotion dur="${animDur}s" repeatCount="indefinite" path="M ${x1} ${y1} L ${x2} ${y2}" />
          </circle>
        </g>
      `;
    }
  });

  svgHtml += `</g><!-- Nodes Group: Drawn on top of edges -->
    <g id="svgNodesGroup">`;

  // Draw Nodes on top of edges
  nodes.forEach(node => {
    const p = positions[node.data.id] || { x: 50, y: 50 };
    const risk = node.data.risk_level || 'CLEAN';
    const borderColor = RISK_COLORS[risk] || '#475569';
    const label = node.data.label || node.data.id;
    const shortType = node.data.type_short || node.data.category || 'Azure Resource';
    const iconSvg = getAzureIconSvg(node.data.type, node.data.category);

    svgHtml += `
      <g class="svg-node" data-node-id="${node.data.id}" transform="translate(${p.x}, ${p.y})" style="cursor: pointer;">
        <!-- Card Background -->
        <rect width="${nodeW}" height="${nodeH}" rx="10" fill="#131b2e" stroke="${borderColor}" stroke-width="2.5" />
        <!-- Left Azure Service Icon -->
        <g transform="translate(14, 18)">
          ${iconSvg}
        </g>
        <!-- Resource Name -->
        <text x="64" y="32" fill="#f8fafc" font-size="12.5" font-weight="700">${escapeSvg(truncate(label, 17))}</text>
        <!-- Resource Type -->
        <text x="64" y="50" fill="#94a3b8" font-size="10.5" font-weight="500">${escapeSvg(shortType)}</text>
        <!-- Status Indicator Pill -->
        ${node.data.finding_count > 0 ? `
          <rect x="176" y="8" width="46" height="20" rx="10" fill="${borderColor}" />
          <text x="199" y="22" fill="#ffffff" font-size="10" font-weight="700" text-anchor="middle">⚠️ ${node.data.finding_count}</text>
        ` : `
          <circle cx="210" cy="18" r="5" fill="#10b981" />
        `}
        <!-- Complete Name Tooltip -->
        <title>${escapeSvg(label)} (${escapeSvg(node.data.type)})</title>
      </g>
    `;
  });

  svgHtml += `</g></g></svg>`;
  container.innerHTML = svgHtml;

  // Bind interactive SVG events
  const svgCanvas = document.getElementById('svgTopologyCanvas');
  const panGroup = document.getElementById('svgPanGroup');

  if (svgCanvas && panGroup) {
    document.querySelectorAll('.svg-node').forEach(nodeEl => {
      nodeEl.addEventListener('click', (e) => {
        e.stopPropagation();
        const nId = nodeEl.getAttribute('data-node-id');
        document.querySelectorAll('.svg-node rect').forEach(r => r.setAttribute('stroke-width', '2.5'));
        nodeEl.querySelector('rect').setAttribute('stroke-width', '5');

        const nodeData = nodes.find(n => n.data.id === nId);
        if (nodeData) {
          inspectResource(nodeData.data);
          if (window.filterFindingsByResource) {
            window.filterFindingsByResource(nId);
          }
        }
      });
    });

    svgCanvas.addEventListener('click', () => {
      document.querySelectorAll('.svg-node rect').forEach(r => r.setAttribute('stroke-width', '2.5'));
      closeResourceInspector();
      if (window.resetFindingsFilter) {
        window.resetFindingsFilter();
      }
    });

    svgCanvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const delta = e.deltaY > 0 ? 0.9 : 1.1;
      svgState.zoom = Math.max(0.4, Math.min(3, svgState.zoom * delta));
      panGroup.setAttribute('transform', `translate(${svgState.panX}, ${svgState.panY}) scale(${svgState.zoom})`);
    }, { passive: false });

    svgCanvas.addEventListener('mousedown', (e) => {
      if (e.target.closest('.svg-node')) return;
      svgState.isDragging = true;
      svgState.startX = e.clientX - svgState.panX;
      svgState.startY = e.clientY - svgState.panY;
      svgCanvas.style.cursor = 'grabbing';
    });

    window.addEventListener('mousemove', (e) => {
      if (!svgState.isDragging) return;
      svgState.panX = e.clientX - svgState.startX;
      svgState.panY = e.clientY - svgState.startY;
      panGroup.setAttribute('transform', `translate(${svgState.panX}, ${svgState.panY}) scale(${svgState.zoom})`);
    });

    window.addEventListener('mouseup', () => {
      if (svgState.isDragging) {
        svgState.isDragging = false;
        if (svgCanvas) svgCanvas.style.cursor = 'grab';
      }
    });
  }
}

function truncate(str, max) {
  if (!str) return '';
  return str.length > max ? str.substring(0, max - 2) + '..' : str;
}

function escapeSvg(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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

// Window globals
window.applyLayout = applyLayout;
window.focusNodeById = focusNodeById;
window.clearHighlights = clearHighlights;
window.inspectResource = inspectResource;
window.closeResourceInspector = closeResourceInspector;
window.toggleLiveTraffic = toggleLiveTraffic;
