"""AZ-AKS-010: Defender for Containers is disabled."""

from typing import Any, Dict, List

from scanner.rules._aks_enterprise_common import scan_control

RULE_ID = "AZ-AKS-010"
RULE_NAME = "Defender for Containers Protection Disabled"
SEVERITY = "HIGH"
CATEGORY = "Kubernetes"
FRAMEWORKS = {"CIS": "2.1.8", "NIST": "DE.CM-8", "ISO27001": "A.12.6.1", "SOC2": "CC7.1"}
DESCRIPTION = "Microsoft Defender for Containers is disabled, removing managed threat detection for in-scope clusters."
REMEDIATION = "Enable the Containers Defender plan at subscription scope and validate sensor deployment."
PLAYBOOK = "playbooks/cli/fix_az_aks_010.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    return scan_control(azure_client, globals(), "defender")
