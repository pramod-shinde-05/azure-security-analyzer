from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from app.services.template_parser import NormalizedResource

@dataclass
class SecurityFinding:
    finding_id: str
    rule_id: str
    title: str
    description: str
    severity: str                   # 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'
    category: str                   # 'Network Security', 'Storage Security', 'Identity & Access', 'Encryption', 'Logging & Monitoring'
    affected_resource_id: str
    affected_resource_name: str
    affected_resource_type: str
    json_path: str
    evidence: str
    impact: str
    remediation: str
    confidence: str = "Direct"      # 'Direct' or 'Incomplete Evidence'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BaseSecurityRule(ABC):
    """Abstract base class for all deterministic Azure security rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier, e.g. SEC-NET-001."""
        pass

    @property
    @abstractmethod
    def title(self) -> str:
        """Brief descriptive title."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Detailed description of the check."""
        pass

    @property
    @abstractmethod
    def severity(self) -> str:
        """Finding severity."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Category of rule."""
        pass

    @property
    @abstractmethod
    def applicable_resource_types(self) -> List[str]:
        """List of Azure resource types this rule applies to."""
        pass

    @abstractmethod
    def evaluate(self, resource: NormalizedResource, all_resources: List[NormalizedResource], template_context: Dict[str, Any]) -> List[SecurityFinding]:
        """
        Evaluate this rule against a resource.
        Returns a list of SecurityFinding objects if violations are detected.
        """
        pass

