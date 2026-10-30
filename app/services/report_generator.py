import datetime
from typing import List, Dict, Any
from app.services.template_parser import NormalizedResource
from app.security_rules.base_rule import SecurityFinding

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]

class ReportGenerator:
    """Aggregates security scan results, calculates security metrics, and prepares audit reports."""

    def __init__(
        self,
        file_id: str,
        filename: str,
        resources: List[NormalizedResource],
        edges: List[Dict[str, Any]],
        findings: List[SecurityFinding],
        metadata: Dict[str, Any],
        warnings: List[str]
    ):
        self.file_id = file_id
        self.filename = filename
        self.resources = resources
        self.edges = edges
        self.findings = findings
        self.metadata = metadata
        self.warnings = warnings

    def generate_summary(self) -> Dict[str, Any]:
        """Calculates executive summary metrics for dashboard cards."""
        severity_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            sev = f.severity.upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFORMATIONAL"] += 1

        # Count findings per resource
        resource_finding_counts: Dict[str, int] = {}
        for f in self.findings:
            r_name = f.affected_resource_name
            resource_finding_counts[r_name] = resource_finding_counts.get(r_name, 0) + 1

        # Top affected resources
        top_affected = sorted(
            [{"name": k, "count": v} for k, v in resource_finding_counts.items()],
            key=lambda x: x["count"],
            reverse=True
        )[:5]

        # Categories affected
        categories_affected: Dict[str, int] = {}
        for f in self.findings:
            categories_affected[f.category] = categories_affected.get(f.category, 0) + 1

        # Unique rule calculation
        unique_rule_ids = sorted(list({f.rule_id for f in self.findings}))

        return {
            "total_resources": len(self.resources),
            "total_relationships": len(self.edges),
            "total_findings": len(self.findings),
            "unique_rules_count": len(unique_rule_ids),
            "unique_rule_ids": unique_rule_ids,
            "severity_counts": severity_counts,
            "top_affected_resources": top_affected,
            "categories_affected": categories_affected,
            "template_metadata": self.metadata,
            "warnings_count": len(self.warnings),
            "warnings": self.warnings
        }

    def generate_export_report(self) -> Dict[str, Any]:
        """Produces a comprehensive JSON export of the security audit."""
        summary = self.generate_summary()
        return {
            "report_metadata": {
                "report_version": "1.0.0",
                "tool_name": "Azure Security Analyzer",
                "scan_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                "scanned_file": self.filename,
                "file_id": self.file_id
            },
            "summary": summary,
            "findings": [f.to_dict() for f in self.findings],
            "resources": [
                {
                    "id": r.id,
                    "name": r.name,
                    "type": r.type,
                    "category": r.category,
                    "location": r.location,
                    "depends_on": r.depends_on,
                    "json_path": r.json_path
                }
                for r in self.resources
            ],
            "limitations_and_warnings": self.warnings
        }

