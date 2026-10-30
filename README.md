# Azure ARM Security Analyzer & Visualizer

A standalone Python Flask web application that allows users to upload Azure Resource Manager (ARM) JSON templates, interactively visualize the provisioned Azure cloud infrastructure topology, and perform deterministic static security analysis to identify misconfigurations before deployment.

---

## 1. Project Overview

- **Location**: `E:\AzureProject\v1\azure-security-analyzer`
- **Application Type**: Independent Python Flask Web Application + Cytoscape.js & Native SVG Frontend
- **Target File Formats**: Azure Resource Manager (ARM) JSON Templates (`.json`)
- **Key Concepts Synthesized**:
  - **Topology Mapping**: Inspired by [AzureResourceVisualizer](https://github.com/ytechie/AzureResourceVisualizer) (dependency graphs, network associations, category mapping, Azure-style node representations).
  - **Security Auditing**: Inspired by Microsoft's [Template Analyzer](https://github.com/Azure/template-analyzer) (deterministic rule scanning, severity ratings, prescriptive remediation, comprehensive coverage).

> **Note on Independence**: This application is completely standalone. It does not import, invoke, or depend on any binaries, scripts, packages, or build artifacts from either reference repository.

---

## 2. Key Features

- **ARM Template Ingestion & Validation**:
  - Strict JSON syntax and Azure ARM schema validation.
  - Safe file handling with collision-free UUID4 identifiers, directory traversal guards, and file size limits (10 MB).
  - Distinguishes between syntax errors, non-ARM JSON structures, and valid templates with analysis warnings.
- **Safe ARM Expression Resolver (No Python `eval()`)**:
  - Safely evaluates `parameters('paramName')` (using default values).
  - Evaluates `variables('varName')` with chained dependency resolution.
  - Recursively resolves `concat(...)`, `format('{0}-{1}', ...)`, `if(...)`, `equals(...)`, and `resourceId(...)`.
  - Gracefully retains runtime/complex functions (e.g. `reference()`, `listKeys()`) as symbolic placeholders without crashing or producing false positives.
- **Dynamic Graph Layout Selector**:
  - **Tiered Architecture (Default)**: Organizes cloud resources cleanly into logical architectural tiers (Network Ingress & Connectivity $\to$ Compute Workloads $\to$ Backend Data & Storage $\to$ Security & Governance) with balanced multi-column row wrapping.
  - **Connected Clusters**: Physics-based force-directed organic layout clustering resources naturally by their direct topological connections.
  - **Dependency Tree**: Level-ordered hierarchical tree arrangement reflecting deployment and downstream dependencies.
  - **Grid View**: Compact, evenly spaced card matrix for rapid resource inventory inspection.
  - **Fit View Control (`⛶`)**: Instantly auto-fits and centers the entire graph within the container canvas.
  - **Expand / Focus Mode (`⛶`)**: Toggles the canvas to full workspace width by collapsing the findings panel.
  - **Live Wire Traffic Flow (`⚡ Live Traffic`)**: Dynamic animated dashed energy flow showing real-time ingress traffic (Public IP to NIC/App in neon orange) and outgoing data flows (App to Storage, Redis, Database, and Key Vault in emerald green/cyan/purple), with toggleable pause/resume.
- **Azure Infrastructure Visualization**:
  - **Azure-Style Resource Cards**: Generous 230px × 76px cards with official Azure service vector SVG icons (Virtual Machines, VNets, Subnets, NSGs, NICs, Public IPs, Storage Accounts, Key Vaults, Web Apps, SQL Databases, Load Balancers, Application Gateways, Managed Identities, Roles, Automation, Redis, and more).
  - **Visually Differentiated Edges**: Solid and dashed color-coded connections representing deployment dependencies (slate dashed), network links (cyan solid), public IP exposure (orange solid), data flows (emerald green dashed), Key Vault secrets (violet dashed), NSG boundaries (purple dashed), authorization bindings (yellow dotted), app hosting (teal solid), and monitoring destinations (emerald dashed).
  - **Dual Engine Architecture**: Cytoscape.js engine with an automatic, 100% offline Native SVG Topology Visualizer fallback featuring hardware-accelerated animated photon/data packet particles (`<animateMotion>`).
- **Deterministic Security Rule Engine (23 Unique Rules)**:
  - Evaluates 23 unique deterministic security rules spanning Network Security, Storage Security, App Service, Identity & RBAC, Encryption, Secrets, and Logging.
  - Each finding provides severity, category, affected resource, JSON path, evidence snippet, attack impact, and concrete remediation steps.
  - **Separate Metric Reporting**: Uniquely counted rule IDs are tracked and reported separately from total finding instances.
- **Bidirectional Interactivity**:
  - Clicking a finding in the audit list instantly centers, pulses, and highlights the affected node in the topology canvas.
  - Clicking a node opens the Resource Inspector showing configuration properties, risk level, associated findings, and topological links.
- **Exportable Security Reports**:
  - One-click export of the complete security audit report in standard structured JSON format.

---

## 3. Implemented Security Rules Catalog (23 Unique Rules)

| Rule ID | Severity | Category | Rule Title & Purpose | Reference Mapping |
| :--- | :--- | :--- | :--- | :--- |
| **`SEC-NET-001`** | **HIGH** | Network Security | **Unrestricted Inbound SSH Access (Port 22)**: Flags NSG rules allowing port 22 from `*` or `0.0.0.0/0`. | Baseline |
| **`SEC-NET-002`** | **HIGH** | Network Security | **Unrestricted Inbound RDP Access (Port 3389)**: Flags NSG rules allowing port 3389 from `*` or `0.0.0.0/0`. | Baseline |
| **`SEC-NET-003`** | **CRITICAL** | Network Security | **Unrestricted Inbound on All Ports (*)**: Flags NSG rules permitting all protocols/ports from any source. | Baseline |
| **`SEC-NET-004`** | **HIGH** | Network Exposure | **Public IP Assigned Without NSG**: Flags NICs with Public IPs that lack Network Security Group protection. | Baseline |
| **`SEC-NET-005`** | **MEDIUM** | Network Security | **Unrestricted Inbound HTTP Access (Port 80)**: Flags NSG rules allowing cleartext HTTP from internet sources. | Baseline |
| **`SEC-STO-001`** | **HIGH** | Storage Security | **Public Blob Access Allowed**: Flags storage accounts where `allowBlobPublicAccess` is enabled. | Baseline |
| **`SEC-STO-002`** | **HIGH** | Storage Security | **Insecure HTTP Allowed**: Flags storage accounts where `supportsHttpsTrafficOnly` is disabled. | Baseline |
| **`SEC-STO-003`** | **MEDIUM** | Storage Security | **Storage Weak TLS Version**: Flags storage accounts with minimum TLS version omitted or below `TLS1_2`. | Baseline |
| **`SEC-STO-004`** | **LOW** | Storage Security | **Public Network Access Enabled**: Flags storage accounts accessible from all public networks. | Baseline |
| **`SEC-APP-001`** | **HIGH** | App Service | **Remote Debugging Enabled**: Flags Web, API, and Function apps with remote debugging enabled. | `TA-000002`, `000008`, `000014` |
| **`SEC-APP-002`** | **HIGH** | App Service | **FTPS Enforcement Disabled**: Flags App Services where `ftpsState` allows cleartext FTP. | `TA-000003`, `000009`, `000015` |
| **`SEC-APP-003`** | **HIGH** | App Service | **Minimum TLS Version Below 1.2**: Flags App Services allowing legacy TLS 1.0 or 1.1. | `TA-000005`, `000011`, `000017` |
| **`SEC-APP-004`** | **MEDIUM** | App Service | **CORS Allows Wildcard All Origins (*)**: Flags App Services with wildcard `*` allowed origins. | `TA-000006`, `000012`, `000018` |
| **`SEC-APP-005`** | **LOW** | Identity & Access | **Managed Identity Disabled**: Flags App Services that lack a configured Managed Identity. | `TA-000007`, `000013`, `000019` |
| **`SEC-KV-001`** | **HIGH** | Security & Secrets | **Key Vault Soft Delete / Purge Protection Disabled**: Flags Key Vaults lacking deletion protection. | Baseline |
| **`SEC-ID-001`** | **HIGH** | Identity & Access | **Subscription-Scope Owner/Contributor**: Flags role assignments granting privileged roles at root scope. | Baseline |
| **`SEC-ID-002`** | **HIGH** | Identity & Access | **Custom Role Wildcard Actions (*)**: Flags custom role definitions containing wildcard `"*"` permissions. | `TA-000020` |
| **`SEC-ENC-001`** | **MEDIUM** | Encryption & Transit | **App Service HTTPS Disabled**: Flags web apps where `httpsOnly` is false or unset. | `TA-000004`, `000010`, `000016` |
| **`SEC-ENC-002`** | **HIGH** | Encryption & Transit | **SQL Database TDE Disabled**: Flags Azure SQL databases with Transparent Data Encryption disabled. | `TA-000027` |
| **`SEC-ENC-003`** | **LOW** | Encryption & Transit | **Storage Infrastructure Encryption Disabled**: Flags storage accounts lacking secondary encryption. | Baseline |
| **`SEC-AUT-001`** | **HIGH** | Encryption & Secrets | **Automation Variable Asset Unencrypted**: Flags Automation variables created without encryption. | `TA-000021` |
| **`SEC-REDIS-001`**| **HIGH** | Encryption & Transit | **Redis Non-SSL Port Enabled**: Flags Azure Cache for Redis instances with cleartext port 6379 enabled. | `TA-000022` |
| **`SEC-LOG-001`** | **LOW** | Logging & Monitoring | **Missing Diagnostic Settings**: Flags Key Vaults / NSGs deployed without accompanying diagnosticSettings. | `TA-000001` |

> For a complete comparison against all 38 rules from Microsoft's Template Analyzer catalog, see [`docs/security-rule-coverage.md`](docs/security-rule-coverage.md).

---

## 4. Architecture & Project Structure

```text
E:\AzureProject\v1\azure-security-analyzer\
├── app.py                      # Application entry point
├── config.py                   # Development, testing, and production configuration
├── requirements.txt            # Python dependencies (Flask, Werkzeug, pytest)
├── README.md                   # System documentation
├── docs/
│   └── security-rule-coverage.md # Security coverage matrix vs. template-analyzer
│
├── app/
│   ├── __init__.py             # Flask application factory (create_app)
│   ├── routes/
│   │   ├── main.py             # Home page route (/)
│   │   ├── upload.py           # File upload handler & validation (/upload)
│   │   └── analysis.py         # Dashboard, API, export, and demo routes (/analysis/<id>)
│   ├── services/
│   │   ├── template_parser.py  # ARM JSON parser & safe expression evaluator
│   │   ├── dependency_resolver.py # Topology links (dependsOn, NIC, Subnet, NSG, RBAC, etc.)
│   │   ├── resource_mapper.py  # Cytoscape node/edge mapper & risk scoring
│   │   ├── security_scanner.py # Central security rule orchestrator
│   │   └── report_generator.py # Audit metrics and JSON report exporter
│   ├── security_rules/
│   │   ├── base_rule.py        # Abstract BaseSecurityRule & SecurityFinding dataclass
│   │   ├── network_rules.py    # SEC-NET-001 to SEC-NET-005
│   │   ├── storage_rules.py    # SEC-STO-001 to SEC-STO-004
│   │   ├── app_service_rules.py# SEC-APP-001 to SEC-APP-005
│   │   ├── keyvault_rules.py   # SEC-KV-001
│   │   ├── identity_rules.py   # SEC-ID-001 to SEC-ID-002
│   │   ├── encryption_rules.py # SEC-ENC-001..003, SEC-AUT-001, SEC-REDIS-001
│   │   └── logging_rules.py    # SEC-LOG-001
│   └── static/
│       ├── css/style.css       # Complete responsive dark theme
│       └── js/
│           ├── graph.js        # Topology visualizer, SVG icons, and 4 layout algorithms
│           ├── findings.js     # Security findings panel & interactive filtering
│           └── dashboard.js    # Dashboard coordinator & toolbar actions
└── tests/
    ├── conftest.py             # Pytest fixtures and test client
    ├── test_upload.py          # Upload validation tests
    ├── test_parser.py          # ARM parser & expression evaluator tests
    ├── test_graph.py           # Dependency resolution & graph generation tests
    ├── test_dependency_resolver.py # Multi-tier edge resolution & traffic flow tests
    ├── test_security_rules.py  # Security rule tests (positive and negative)
    └── test_report.py          # Summary metrics & JSON report export tests
```

---

## 5. Running the Application

To run the application locally:

```powershell
cd E:\AzureProject\v1\azure-security-analyzer
python app.py
```

The web application starts at `http://127.0.0.1:5000`.

---

## 6. Running the Automated Test Suite

```powershell
cd E:\AzureProject\v1\azure-security-analyzer
pytest
```

---

## 7. Known Limitations & Static Analysis Boundaries

As an offline, pre-deployment static template analyzer, the engine has defined boundaries:

1. **Unresolved Runtime ARM Expressions**:
   - ARM expressions requiring live Azure ARM context (such as `reference(...)`, `listKeys(...)`, runtime deployment outputs, or `uniqueString(subscription().id)`) cannot be evaluated without an active Azure connection.
   - The engine gracefully tags these constructs as `[Symbolic:<expression>]` without failing and records them in analysis warnings banner.
2. **Linked & External Nested Templates**:
   - Templates referencing external template URIs via `Microsoft.Resources/deployments` (`properties.templateLink.uri`) require out-of-band retrieval. Inline nested templates (`properties.template`) are fully parsed.
3. **Runtime & Directory State**:
   - Security configurations dependent on live tenant state (such as Microsoft Entra ID privileged role assignments, Privileged Identity Management (PIM) policies, Azure Policy initiatives, or cost center quotas) are outside the scope of static Infrastructure-as-Code analysis.
4. **Offline Air-Gapped Operation**:
   - The core deterministic application does not require internet connectivity. Vector SVG icons, fallback layouts, Cytoscape/SVG engines, and deterministic security rules function completely offline.

---

## 8. Phase 2: Dual AI Provider Threat Intelligence & Attack-Path Analysis

Phase 2 introduces an optional AI-assisted threat intelligence layer supporting both cloud-hosted **Google Gemini API** and 100% local, air-gapped **Ollama Local API**.

### Key AI Features:
- **Dual AI Provider Architecture**: Switch seamlessly between Google Gemini API (cloud) and Ollama (local private inference) using `AI_PROVIDER=gemini` or `AI_PROVIDER=ollama`. All API keys, endpoints, and model configurations are strictly imported from the `.env` file without hardcoded dummy defaults.
- **Correlated Attack-Path Modeling**: Identifies entry points (Public IPs, open inbound ports) and maps lateral movement paths toward sensitive target resources (Storage, Redis, SQL Databases, Key Vaults, Privileged Roles).
- **Contextual Finding Explanations (`⚡ AI Explain`)**: Generates architectural context, blast radius analysis, attacker perspective, and verification steps for any finding.
- **Remediation Generator & In-Memory Rescan (`🛠️ AI Fix` & `🔬 Dry-Run Rescan`)**: Generates minimal ARM JSON fix snippets and simulates the fix in-memory to verify that the security violation is eliminated before deployment.
- **Strict Grounding & Anti-Hallucination**: Server-side `AIResponseValidator` validates every cited `resource_id` and `finding_id` against the active session inventory.
- **Prompt-Injection Defense & Secret Masking**: Template properties are isolated inside untrusted data boundaries with credentials/secrets redacted before context construction.
- **Deterministic Cache**: Hash-based caching (`AIResponseCache`) prevents redundant inference spending across re-renders.

---

### Configuration & Switching Providers

Create or update `.env` in the project root (see `.env.example`):

#### Option A: Google Gemini API (Cloud)
```env
AI_ENABLED=true
AI_PROVIDER=gemini

GEMINI_API_KEY=AIzaSy...your_gemini_api_key_here
GEMINI_MODEL=gemini-3.5-flash

AI_REQUEST_TIMEOUT=60
AI_MAX_RETRIES=2
AI_CACHE_ENABLED=true
```
*Note: If `gemini-3.5-flash` is unreleased or returns 404, the system automatically falls back to the recommended supported model `gemini-2.0-flash`.*

#### Option B: Local Ollama (Private / Air-Gapped)
```env
AI_ENABLED=true
AI_PROVIDER=ollama

OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen3.5

AI_REQUEST_TIMEOUT=60
AI_MAX_RETRIES=2
AI_CACHE_ENABLED=true
```

To run Ollama locally:
1. Start Ollama: `ollama serve`
2. Pull your chosen model: `ollama pull qwen3.5` (or `llama3.2`, `mistral`, `phi3`)
3. Set `AI_PROVIDER=ollama` in `.env`.

---

### Automated Testing

All automated tests use mocked provider fixtures and do not consume live API quota or require internet access:
```powershell
cd E:\AzureProject\v1\azure-security-analyzer
pytest tests/test_ai_provider.py
pytest tests/
```
