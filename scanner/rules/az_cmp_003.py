"""AZ-CMP-003: VM without endpoint protection installed."""

import logging
from typing import Any, Dict, List, Optional, Tuple

RULE_ID = "AZ-CMP-003"
RULE_NAME = "VM Without Endpoint Protection Installed"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {
    "CIS": "8.2",
    "NIST": "DE.CM-4",
    "ISO27001": "A.12.2.1",
    "SOC2": "CC6.8",
}
DESCRIPTION = (
    "VM has no recognised endpoint protection extension installed. "
    "Without it malware and ransomware can run undetected. "
    "CIS 8.2 requires an approved AV/EDR solution on all VMs."
)
REMEDIATION = "Install IaaSAntimalware or onboard to MDE (MDE.Windows / MDE.Linux) depending on the OS."
PLAYBOOK = "playbooks/cli/fix_az_cmp_003.sh"

# Microsoft Defender for Cloud's "Endpoint protection" assessment reports real
# runtime health of the installed agent - a stronger signal than checking
# whether a named extension is merely present. When Defender confirms
# Unhealthy, that is a confirmed violation even if a recognised extension is
# installed (the earlier, weaker signal this rule used to rely on alone).
DEFENDER_UNHEALTHY_DESCRIPTION = (
    "Microsoft Defender for Cloud reports the 'Endpoint protection' security assessment for "
    "this VM as Unhealthy. This is real agent health telemetry from Defender for Cloud, not "
    "just extension-name presence, so it overrides an otherwise-installed recognised extension."
)
DEFENDER_UNHEALTHY_REMEDIATION = (
    "Open Defender for Cloud > Recommendations > 'Endpoint protection should be installed on "
    "your machines', review why the agent is reporting unhealthy on this VM, and remediate "
    "(reinstall/repair the AV/EDR agent, resolve conflicting security products)."
)

# A recognised EP extension whose provisioning_state is present and is not
# "Succeeded" is not actually protecting the VM - name presence alone was
# the previous (weak) signal. This is surfaced as an indeterminate result,
# not a confirmed absence of endpoint protection, since a transient/failed
# provisioning state does not prove malware protection is truly off.
INDETERMINATE_SEVERITY = "LOW"
INDETERMINATE_DESCRIPTION = (
    "A recognised endpoint protection extension is installed but its provisioning state is "
    "missing or does not confirm successful completion, so effective protection cannot be "
    "confirmed. This is not a confirmed absence of endpoint protection."
)
INDETERMINATE_REMEDIATION = (
    "Check the extension's status in the Azure Portal (VM > Extensions) and, if failed or "
    "stuck, remove and reinstall it, then re-run the scan to confirm successful provisioning."
)

KNOWN_EP_EXTENSIONS = {
    "microsoftmonitoringagent",
    "mde.linux",
    "mde.windows",
    "iaasantimalware",
}

logger = logging.getLogger(__name__)


# Microsoft renamed this Defender for Cloud recommendation from "Endpoint
# protection should be installed..." to "EDR solution should be installed
# on virtual machines" when it moved from the deprecated Log Analytics
# agent to agentless EDR scanning. Matching only "endpoint protection"
# means the index silently matches nothing against a current subscription's
# real assessment data, so Defender's signal is never found and every VM
# falls back to the weaker extension-name check - accept either name.
#
# The second marker is the full recommendation title, not the bare
# substring "edr solution": a bare substring match risks silently pulling
# in a future, unrelated Defender recommendation that happens to contain
# those two words, misattributing its status to this rule's endpoint-
# protection determination.
_ENDPOINT_PROTECTION_DISPLAY_NAME_MARKERS = ("endpoint protection", "edr solution should be installed")


def _index_endpoint_protection_assessments(assessments: Optional[List[Any]]) -> Dict[str, List[Any]]:
    """Group the subscription-wide assessments list by resource ID, once per scan.

    The assessments API only supports subscription/management-group scope, so
    every VM's lookup would otherwise re-scan the full list. Building this
    index up front makes each VM's lookup O(1) instead of O(assessment count).
    """
    index: Dict[str, List[Any]] = {}
    for assessment in assessments or []:
        display_name = (getattr(assessment, "display_name", "") or "").lower()
        if not any(marker in display_name for marker in _ENDPOINT_PROTECTION_DISPLAY_NAME_MARKERS):
            continue
        resource_details = getattr(assessment, "resource_details", None)
        resource_id = (getattr(resource_details, "id", "") or "").lower()
        if not resource_id:
            continue
        index.setdefault(resource_id, []).append(assessment)
    return index


def _defender_endpoint_protection_status(assessments_by_resource: Dict[str, List[Any]], vm_id: str) -> Optional[bool]:
    """Look up the Defender for Cloud 'Endpoint protection' assessment for a VM.

    A resource can have more than one assessment whose display name contains
    "endpoint protection" (e.g. an installation check and a separate health
    check). Resolving by "first match in the list" would make the result
    depend on API response order, so instead every matching assessment for
    the resource is considered and an "Unhealthy" code always wins - a real
    unhealthy signal must never be masked by iteration order.

    Returns:
        True  - all matching assessments are "Healthy" (confirmed protected).
        False - at least one matching assessment is "Unhealthy" (confirmed
                unprotected).
        None  - no assessment matched this VM, or none had a status code of
                "Healthy"/"Unhealthy" (e.g. only "NotApplicable"). Callers
                must treat this as "Defender signal unavailable" and fall
                back to the extension-based check, never as compliant.
    """
    matches = assessments_by_resource.get((vm_id or "").lower())
    if not matches:
        return None

    codes = set()
    for assessment in matches:
        status = getattr(assessment, "status", None)
        codes.add((getattr(status, "code", "") or "").lower())

    if "unhealthy" in codes:
        return False
    if "healthy" in codes:
        return True
    return None  # Only NotApplicable or unrecognised status codes.


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    assessments_by_resource = _index_endpoint_protection_assessments(azure_client.get_security_assessments())

    for vm in azure_client.get_virtual_machines():
        vm_id = getattr(vm, "id", "")
        parsed = azure_client.parse_resource_id(vm_id)
        rg = parsed.get("resource_group", "")
        vm_name = parsed.get("name", "")
        if not rg or not vm_name:
            continue

        defender_status = _defender_endpoint_protection_status(assessments_by_resource, vm_id)

        if defender_status is True:
            continue  # Defender confirms protected - the strongest available signal.

        if defender_status is False:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vm.id,
                    "resource_name": vm_name,
                    "resource_type": "Microsoft.Compute/virtualMachines",
                    "description": DEFENDER_UNHEALTHY_DESCRIPTION,
                    "remediation": DEFENDER_UNHEALTHY_REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": rg,
                        "signal": "defender_assessment",
                        "determination": "non_compliant",
                    },
                }
            )
            continue

        # Defender signal unavailable (not onboarded, no assessment yet, API
        # failure) - fall back to the extension-name/provisioning-state check.
        exts = azure_client.get_vm_extensions(rg, vm_name)
        if exts is None:
            continue

        installed: List[Tuple[str, Any]] = []
        for e in exts:
            t = (
                getattr(e, "type_properties_type", None)
                or getattr(e, "virtual_machine_extension_type", None)
                or getattr(e, "type", "")
            )
            if t:
                installed.append((t.lower(), e))

        installed_names = sorted({name for name, _ in installed})
        matched = [(name, ext) for name, ext in installed if name in KNOWN_EP_EXTENSIONS]

        if not matched:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vm.id,
                    "resource_name": vm_name,
                    "resource_type": "Microsoft.Compute/virtualMachines",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": rg,
                        "installed_extensions": installed_names,
                        "signal": "extension_fallback",
                        "determination": "non_compliant",
                    },
                }
            )
            continue

        # A recognised EP extension is installed - name presence alone is not
        # enough. An extension is only treated as confirmed healthy when its
        # provisioning_state is exactly "Succeeded". A missing/unexposed
        # provisioning_state does not prove the extension succeeded any more
        # than it proves it failed - it's unknown evidence, not a pass - so
        # it's surfaced as indeterminate together with any other
        # non-"Succeeded" state (Failed, Canceled, ...) rather than silently
        # passed.
        #
        # Every matched extension is checked - not just the first. Records
        # are grouped by extension name first: two API records for the same
        # extension (e.g. a transient re-sync reporting Failed then
        # Succeeded) are one signal, and that name is healthy if any record
        # for it succeeded. But two *different* recognised extensions are
        # separate signals, and the same "unconfirmed wins" precedent as the
        # Defender-assessment branch above applies across them - a VM with
        # IaaSAntimalware Succeeded and MDE.Linux Failed is not compliant
        # just because one of the two came up healthy. Stopping at the first
        # Succeeded record would silently drop the failed extension from
        # both the verdict and unconfirmed_names.
        states_by_name: Dict[str, List[str]] = {}
        for name, ext in matched:
            provisioning_state = (getattr(ext, "provisioning_state", None) or "").lower()
            states_by_name.setdefault(name, []).append(provisioning_state)

        unconfirmed_names = [name for name, states in states_by_name.items() if "succeeded" not in states]
        any_confirmed_healthy = any("succeeded" in states for states in states_by_name.values())

        if any_confirmed_healthy and not unconfirmed_names:
            continue

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": INDETERMINATE_SEVERITY,
                "category": CATEGORY,
                "resource_id": vm.id,
                "resource_name": vm_name,
                "resource_type": "Microsoft.Compute/virtualMachines",
                "description": INDETERMINATE_DESCRIPTION,
                "remediation": INDETERMINATE_REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": rg,
                    "installed_extensions": installed_names,
                    "unconfirmed_extensions": sorted(set(unconfirmed_names)),
                    "signal": "extension_fallback",
                    "determination": "indeterminate",
                },
            }
        )

    return findings
