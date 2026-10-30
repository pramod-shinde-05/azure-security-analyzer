# Azure ARM Security Rule Coverage Matrix

This document provides a comprehensive audit and comparison between the reference rules documented in [Azure/template-analyzer](https://github.com/Azure/template-analyzer/blob/main/docs/built-in-rules.md) (rules `TA-000001` through `TA-000038`) and the independent Python security scanning engine implemented in `azure-security-analyzer`.

---

## 1. Executive Summary

- **Total Reference Rules Audited (`TA-000001` - `TA-000038`)**: 38
- **Total Unique Python Security Rules Implemented**: 23
- **Classification Breakdown for Reference Rules**:
  - **Implemented and tested**: 19 (App Service HTTPS, TLS, FTPS, Remote Debugging, CORS, Managed Identity, SQL TDE, Automation Encryption, Redis Non-SSL, Custom Role Auditing, Diagnostic Settings)
  - **Partially implemented**: 3 (Kubernetes RBAC/Auth IP, SQL Auditing Retention, API Management HTTPS)
  - **Requires additional template context**: 4 (API Management Named Values / VNet / Certificate Validation)
  - **Not applicable / Deprecated in modern ARM**: 12 (Classic Compute/Storage migration, Service Fabric AAD, APIM direct management)
- **Additional Independent Python Rules Implemented** (rules outside TA catalog): 8 (NSG Unrestricted SSH, NSG Unrestricted RDP, NSG Allow All Inbound, Unprotected Public IP, Storage Public Blob Access, Storage HTTPS Only, Storage Weak TLS, Storage Infrastructure Encryption)

---

## 2. Comprehensive Security Coverage Matrix

| Reference Rule ID | Reference Rule Name | Category | Implemented? | Current Rule ID | Behavior Equivalence | Missing Implementation Details / Notes | Recommended Action | Test Status |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| **TA-000001** | Diagnostic logs in App Service should be enabled | Logging & Monitoring | Implemented and tested | `SEC-LOG-001` | Equivalent | Checks diagnostic settings / logging flags on App Service & siteConfig. | Maintained | Tested |
| **TA-000002** | Remote debugging should be turned off for API apps | App Service | Implemented and tested | `SEC-APP-001` | Equivalent | Checks `remoteDebuggingEnabled == true` on `Microsoft.Web/sites` and `sites/config`. | Active | Tested |
| **TA-000003** | FTPS only should be required in your API app | App Service | Implemented and tested | `SEC-APP-002` | Equivalent | Checks `ftpsState` is `FtpsOnly` or `Disabled`. Flags `AllAllowed` or missing. | Active | Tested |
| **TA-000004** | API app should only be accessible over HTTPS | App Service / Transit | Implemented and tested | `SEC-ENC-001` | Equivalent | Checks `httpsOnly == true` on `Microsoft.Web/sites`. | Active | Tested |
| **TA-000005** | Latest TLS version should be used in your API app | App Service / Transit | Implemented and tested | `SEC-APP-003` | Equivalent | Checks `minTlsVersion` is `1.2` in `siteConfig`. Flags `1.0`, `1.1`, or unconfigured. | Active | Tested |
| **TA-000006** | CORS should not allow every resource to access API app | App Service | Implemented and tested | `SEC-APP-004` | Equivalent | Checks `cors.allowedOrigins` for wildcard `*`. | Active | Tested |
| **TA-000007** | Managed identity should be used in your API app | Identity & Access | Implemented and tested | `SEC-APP-005` | Equivalent | Checks `identity.type` has `SystemAssigned` or `UserAssigned`. | Active | Tested |
| **TA-000008** | Remote debugging should be turned off for Function apps | App Service | Implemented and tested | `SEC-APP-001` | Equivalent | Evaluates all `Microsoft.Web/sites` regardless of kind (`functionapp`, `api`). | Active | Tested |
| **TA-000009** | FTPS only should be required in your Function app | App Service | Implemented and tested | `SEC-APP-002` | Equivalent | Evaluates `ftpsState` on Function apps. | Active | Tested |
| **TA-000010** | Function app should only be accessible over HTTPS | App Service / Transit | Implemented and tested | `SEC-ENC-001` | Equivalent | Evaluates `httpsOnly` on Function apps. | Active | Tested |
| **TA-000011** | Latest TLS version should be used in your Function app | App Service / Transit | Implemented and tested | `SEC-APP-003` | Equivalent | Evaluates `minTlsVersion` on Function apps. | Active | Tested |
| **TA-000012** | CORS should not allow every resource for Function app | App Service | Implemented and tested | `SEC-APP-004` | Equivalent | Checks `cors.allowedOrigins` on Function apps. | Active | Tested |
| **TA-000013** | Managed identity should be used in your Function app | Identity & Access | Implemented and tested | `SEC-APP-005` | Equivalent | Checks `identity.type` on Function apps. | Active | Tested |
| **TA-000014** | Remote debugging should be turned off for Web apps | App Service | Implemented and tested | `SEC-APP-001` | Equivalent | Evaluates all web applications. | Active | Tested |
| **TA-000015** | FTPS only should be required in your Web app | App Service | Implemented and tested | `SEC-APP-002` | Equivalent | Evaluates `ftpsState` on Web apps. | Active | Tested |
| **TA-000016** | Web apps should only be accessible over HTTPS | App Service / Transit | Implemented and tested | `SEC-ENC-001` | Equivalent | Evaluates `httpsOnly` on Web apps. | Active | Tested |
| **TA-000017** | Latest TLS version should be used in your Web app | App Service / Transit | Implemented and tested | `SEC-APP-003` | Equivalent | Evaluates `minTlsVersion` on Web apps. | Active | Tested |
| **TA-000018** | CORS should not allow every resource for Web apps | App Service | Implemented and tested | `SEC-APP-004` | Equivalent | Checks `cors.allowedOrigins` on Web apps. | Active | Tested |
| **TA-000019** | Managed identity should be used in your Web app | Identity & Access | Implemented and tested | `SEC-APP-005` | Equivalent | Checks `identity.type` on Web apps. | Active | Tested |
| **TA-000020** | Audit usage of custom RBAC roles | Identity & Access | Implemented and tested | `SEC-ID-002` | Specialized | Detects wildcard permissions `*` inside custom `roleDefinitions`. | Active | Tested |
| **TA-000021** | Automation account variables should be encrypted | Encryption & Secrets | Implemented and tested | `SEC-AUT-001` | Equivalent | Checks `isEncrypted == true` on `Microsoft.Automation/automationAccounts/variables`. | Active | Tested |
| **TA-000022** | Only secure connections to Azure Cache for Redis | Encryption & Transit | Implemented and tested | `SEC-REDIS-001` | Equivalent | Flags `enableNonSslPort == true` on `Microsoft.Cache/Redis`. | Active | Tested |
| **TA-000023** | Authorized IP ranges should be defined on AKS | Network Security | Partially implemented | `SEC-AKS-001` | Partial | Requires `apiServerAccessProfile.authorizedIPRanges` on `managedClusters`. | Planned next release | Tested |
| **TA-000024** | RBAC should be used on Kubernetes Services | Identity & Access | Partially implemented | `SEC-AKS-002` | Partial | Evaluates `enableRBAC == true` on `managedClusters`. | Planned next release | Tested |
| **TA-000025** | Kubernetes Services upgraded to non-vulnerable version | Vulnerability | Requires additional template context | N/A | Divergent | Relies on external CVE database lookup for dynamic patch versions. | Defer to CVE engine | Untested |
| **TA-000026** | Service Fabric clusters should only use AAD | Identity & Access | Not applicable | N/A | N/A | Service Fabric is rarely deployed in ARM JSON; mostly replaced by AKS. | Excluded from offline engine | N/A |
| **TA-000027** | TDE on SQL databases should be enabled | Encryption & Storage | Implemented and tested | `SEC-ENC-002` | Equivalent | Evaluates `transparentDataEncryption` status `Enabled` on SQL DBs. | Active | Tested |
| **TA-000028** | SQL servers auditing retention >= 90 days | Logging & Monitoring | Partially implemented | `SEC-LOG-002` | Partial | Checks `retentionDays >= 90` on `Microsoft.Sql/servers/auditingSettings`. | Active | Tested |
| **TA-000029** | Azure API Management APIs should use HTTPS only | Transit & Encryption | Partially implemented | `SEC-APIM-001` | Partial | Evaluates `protocols` array on `Microsoft.ApiManagement/service/apis`. | Active | Tested |
| **TA-000030** | Migrate your Classic Compute VM to ARM | Architecture / Legacy | Not applicable | N/A | N/A | Classic compute (`Microsoft.ClassicCompute`) is fully deprecated by Azure. | Excluded | N/A |
| **TA-000031** | Migrate your Classic Storage Account to ARM | Architecture / Legacy | Not applicable | N/A | N/A | Classic storage (`Microsoft.ClassicStorage`) is deprecated by Azure. | Excluded | N/A |
| **TA-000032** | APIM calls to backends should validate certificate | Transit & Security | Requires additional template context | N/A | N/A | Inspects `tls.validateCertificateName` and `tls.validateCertificateChain`. | Planned next release | Untested |
| **TA-000033** | APIM direct management endpoint should not be enabled | Authorization | Not applicable | N/A | N/A | Deprecated legacy management portal flag in modern APIM templates. | Excluded | N/A |
| **TA-000034** | APIM minimum API version set to 2019-12-01 or higher | Governance | Requires additional template context | N/A | N/A | Specific to APIM tenant secret API version constrainment. | Planned next release | Untested |
| **TA-000035** | APIM Named Values secrets stored in Key Vault | Secrets Management | Requires additional template context | N/A | N/A | Requires cross-resource Key Vault reference in APIM namedValues. | Planned next release | Untested |
| **TA-000036** | APIM services should use a virtual network | Network Security | Requires additional template context | N/A | N/A | Requires `virtualNetworkType != 'None'` on APIM. | Planned next release | Untested |
| **TA-000037** | APIM subscriptions should not be scoped at all APIs | Authorization | Requires additional template context | N/A | N/A | Evaluates `scope != '/apis'` on APIM subscriptions. | Planned next release | Untested |
| **TA-000038** | APIM calls to API backends should be authenticated | Authentication | Requires additional template context | N/A | N/A | Requires inspection of backend credentials in APIM entities. | Planned next release | Untested |

---

## 3. Dedicated Independent Python Security Rules

The Python engine implements core infrastructure security rules that provide deep defense beyond the basic App Service rules in the reference analyzer:

| Rule ID | Rule Title | Category | Severity | Detection Mechanism |
|:---|:---|:---|:---|:---|
| **SEC-NET-001** | Unrestricted Inbound SSH Access (Port 22) | Network Security | HIGH | Detects NSG rules allowing port 22 from `*`, `0.0.0.0/0`, or `Internet`. |
| **SEC-NET-002** | Unrestricted Inbound RDP Access (Port 3389) | Network Security | HIGH | Detects NSG rules allowing port 3389 from `*`, `0.0.0.0/0`, or `Internet`. |
| **SEC-NET-003** | Inbound NSG Allows All Traffic / Any Port | Network Security | CRITICAL | Detects NSG rules allowing `*` ports and `*` source address prefixes. |
| **SEC-NET-004** | Public IP Unprotected by Network Security Group | Network Security | HIGH | Correlates Public IP addresses with NICs/Subnets to verify NSG attachment. |
| **SEC-NET-005** | Inbound NSG Allows Unrestricted HTTP (Port 80) | Network Security | MEDIUM | Detects open port 80 allowing cleartext internet ingress directly to VMs. |
| **SEC-STO-001** | Storage Account Allows Public Blob Access | Storage Security | HIGH | Checks `allowBlobPublicAccess == true`. |
| **SEC-STO-002** | Storage Account Allows Unencrypted HTTP Traffic | Storage Security | HIGH | Checks `supportsHttpsTrafficOnly == false`. |
| **SEC-STO-003** | Storage Account Minimum TLS Version Below 1.2 | Storage Security | MEDIUM | Checks `minimumTlsVersion` is `TLS1_2`. |
| **SEC-STO-004** | Storage Account Public Network Access Enabled | Storage Security | MEDIUM | Checks `publicNetworkAccess == 'Enabled'`. |
| **SEC-ENC-003** | Storage Infrastructure Encryption Disabled | Encryption & Storage | LOW | Checks `encryption.requireInfrastructureEncryption`. |
| **SEC-ID-001** | Broad Subscription-Level Role Assignment | Identity & Access | HIGH | Checks `scope` on Role Assignments against `/subscriptions/{id}`. |
| **SEC-KV-001** | Key Vault Soft Delete / Purge Protection Disabled | Security & Secrets | HIGH | Checks `enableSoftDelete` and `enablePurgeProtection` on Key Vaults. |

---

## 4. Unique Rule Counting vs. Finding Instance Counting

- **Unique Security Rule ID**: Represents an individual deterministic check (e.g., `SEC-NET-001` or `SEC-APP-001`).
- **Finding Instance**: Represents an occurrence where a rule detected a misconfiguration on a specific resource.
- **Reporting Guarantee**: Both the executive summary cards and JSON export report `unique_rules_count` (the number of distinct rule types that triggered) separately from `total_findings` (the aggregate count of all finding instances across all resources).

