"""AZ-CMP-004: VM without automatic OS patching enabled."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

RULE_ID = "AZ-CMP-004"
RULE_NAME = "VM Without Automatic OS Patching Enabled"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {
    "CIS": "8.3",
    "NIST": "PR.IP-12",
    "ISO27001": "A.12.6.1",
    "SOC2": "CC7.1",
}
DESCRIPTION = (
    "VM does not have automatic OS patching enabled. "
    "Unpatched VMs are vulnerable to known exploits. "
    "CIS 8.3 requires OS patches are applied in a timely manner."
)
REMEDIATION = (
    "For Windows VMs enable automatic updates via osProfile.windowsConfiguration "
    "or set patchMode to AutomaticByPlatform. "
    "For Linux VMs set patchMode to AutomaticByPlatform."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_004.sh"

# A VM can look compliant by config (auto-updates/AutomaticByPlatform set)
# while still being months behind on real patches, if the platform simply
# hasn't applied anything yet. Real assessment evidence (Azure Update
# Manager / Microsoft.Maintenance, surfaced through the VM's instance view)
# can override a config-only pass into a confirmed finding. It never
# suppresses a config-based finding: config with auto-patching disabled is
# itself an unmanaged-drift risk regardless of today's patch snapshot, so
# the config-flag check always remains the fallback/baseline signal.
ASSESSMENT_OVERRIDE_DESCRIPTION = (
    "VM is configured for automatic OS patching, but its latest Azure Update Manager patch "
    "assessment shows critical or security patches are still pending installation. Config "
    "alone does not prove patches have actually been applied - this is real assessment "
    "evidence that the VM is currently unpatched."
)
ASSESSMENT_OVERRIDE_REMEDIATION = (
    "Trigger an on-demand patch installation (Update Manager > Install now) or review why "
    "the scheduled automatic patching run has not applied the pending critical/security "
    "patches, then re-run the scan to confirm the assessment clears."
)

# An assessment run whose status confirms it actually completed and produced
# real counts. Anything else (in progress, failed, unknown) is not reliable
# enough evidence to override a config-based pass.
_CONCLUSIVE_ASSESSMENT_STATUSES = {"succeeded", "completedwithwarnings"}

# A "clean" assessment (zero pending critical/security patches) only counts
# as real evidence of the VM's *current* state while it's recent - Azure
# doesn't re-run this automatically on a fixed schedule, so an old clean
# result proves nothing about patches that have become available since.
STALE_ASSESSMENT_THRESHOLD_DAYS = 30

# An unavailable, non-conclusive, or stale assessment means config alone is
# the only signal - which is real evidence config is correctly set, but not
# proof patches have actually landed. Surfaced as indeterminate rather than
# silently treated as a clean pass, the same LOW/indeterminate split used by
# AZ-CMP-001/003 for their own unresolvable evidence.
INDETERMINATE_SEVERITY = "LOW"
INDETERMINATE_DESCRIPTION = (
    "VM is configured for automatic OS patching, but its real Azure Update Manager patch "
    "assessment is unavailable, did not complete successfully, or is older than "
    f"{STALE_ASSESSMENT_THRESHOLD_DAYS} days, so the VM's actual current patch state cannot "
    "be confirmed. Config alone is not proof patches have actually been applied."
)
INDETERMINATE_REMEDIATION = (
    "Trigger an on-demand patch assessment (Update Manager > Check for updates) so a current "
    "result exists, then re-run the scan to confirm the VM's real patch state."
)

# Benign clock skew between Azure's control plane and the scanner host is
# expected; a timestamp further ahead of "now" than this is implausible and
# is treated as bad data, not as a brand-new assessment.
CLOCK_SKEW_TOLERANCE = timedelta(minutes=5)

logger = logging.getLogger(__name__)


def _is_fresh(last_modified_time: Any) -> bool:
    """Return True only when last_modified_time parses to a UTC-aware timestamp
    that is within the staleness threshold and not materially in the future.
    Missing or unparseable data is not fresh - absence of a usable timestamp
    must never be read as "recent enough" - and a timestamp far ahead of now
    is clock skew / bad data, not evidence of a just-completed assessment."""
    if isinstance(last_modified_time, datetime):
        observed = last_modified_time
    elif isinstance(last_modified_time, str):
        try:
            observed = datetime.fromisoformat(last_modified_time.replace("Z", "+00:00"))
        except ValueError:
            return False
    else:
        return False
    if observed.tzinfo is None:
        return False
    age = datetime.now(timezone.utc) - observed
    if age < -CLOCK_SKEW_TOLERANCE:
        return False
    return age.days <= STALE_ASSESSMENT_THRESHOLD_DAYS


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        parsed = azure_client.parse_resource_id(getattr(vm, "id", ""))
        rg = parsed.get("resource_group", "")
        vm_name = parsed.get("name", "")
        if not rg or not vm_name:
            continue

        os_profile = getattr(vm, "os_profile", None)
        if not os_profile:
            continue

        patching_ok = False

        win_config = getattr(os_profile, "windows_configuration", None)
        if win_config is not None:
            auto_updates = getattr(win_config, "enable_automatic_updates", False)
            patch_settings = getattr(win_config, "patch_settings", None)
            patch_mode = getattr(patch_settings, "patch_mode", "") if patch_settings else ""
            if auto_updates or (patch_mode or "").lower() == "automaticbyplatform":
                patching_ok = True

        linux_config = getattr(os_profile, "linux_configuration", None)
        if linux_config is not None:
            patch_settings = getattr(linux_config, "patch_settings", None)
            patch_mode = getattr(patch_settings, "patch_mode", "") if patch_settings else ""
            if (patch_mode or "").lower() == "automaticbyplatform":
                patching_ok = True

        if not patching_ok:
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
                        "signal": "config_flags",
                        "determination": "non_compliant",
                    },
                }
            )
            continue

        # Config says patching is enabled - check real assessment evidence.
        # This can raise the result two ways: a conclusive, fresh assessment
        # with pending critical/security patches overrides the config-based
        # pass into a confirmed finding (the false-negative case: config
        # correct, platform hasn't actually applied anything yet). Anything
        # short of that - unavailable, non-conclusive, or stale evidence -
        # is not proof patches were applied either, so it's surfaced as
        # indeterminate rather than silently left as a clean pass.
        def _indeterminate_finding(reason: str, patch_summary: Any = None) -> Dict[str, Any]:
            metadata: Dict[str, Any] = {
                "resource_group": rg,
                "signal": "patch_assessment_inconclusive",
                "determination": "indeterminate",
                "reason": reason,
            }
            if patch_summary is not None:
                metadata["assessment_status"] = (getattr(patch_summary, "status", "") or "").lower()
                metadata["last_modified_time"] = str(getattr(patch_summary, "last_modified_time", "") or "") or None
            return {
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
                "metadata": metadata,
            }

        patch_summary = azure_client.get_vm_patch_status(rg, vm_name)
        if patch_summary is None:
            findings.append(_indeterminate_finding("assessment_unavailable"))
            continue

        status = (getattr(patch_summary, "status", "") or "").lower()
        if status not in _CONCLUSIVE_ASSESSMENT_STATUSES:
            findings.append(_indeterminate_finding("assessment_not_conclusive", patch_summary))
            continue

        critical_count = getattr(patch_summary, "critical_and_security_patch_count", None)
        if critical_count is None:
            findings.append(_indeterminate_finding("patch_count_unavailable", patch_summary))
            continue

        # A patch count - zero or nonzero - only describes the VM's *current*
        # patch state while the assessment behind it is recent. Azure does not
        # re-run this on a fixed schedule, so a stale, missing, or implausible
        # timestamp means the count could predate patches that have since been
        # installed (a nonzero count would then be a false-positive HIGH) or
        # that have since become available (a zero count would be a false
        # clean pass). Gate on a usable, current timestamp before trusting the
        # count either way.
        if not _is_fresh(getattr(patch_summary, "last_modified_time", None)):
            findings.append(_indeterminate_finding("assessment_stale", patch_summary))
            continue

        if critical_count > 0:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vm.id,
                    "resource_name": vm_name,
                    "resource_type": "Microsoft.Compute/virtualMachines",
                    "description": ASSESSMENT_OVERRIDE_DESCRIPTION,
                    "remediation": ASSESSMENT_OVERRIDE_REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": rg,
                        "signal": "patch_assessment_override",
                        "determination": "non_compliant",
                        "critical_and_security_patch_count": critical_count,
                        "other_patch_count": getattr(patch_summary, "other_patch_count", None),
                        "assessment_status": status,
                    },
                }
            )

    return findings
