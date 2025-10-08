import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import pytest
from tests.helpers.firewall import (
    get_security_policies,
    get_policy_terms,
    should_test_device
)
from typing import Dict, Any, Set

REQUIREMENT_6 = "EG-FW-6: Remote admin protocols must be restricted to SSHv2, IPsec, or TLS"

# Define accepted remote admin protocols
DEFAULT_ALLOWED_ADMIN_PROTOCOLS = {"junos-ssh", "IKE", "IKE-NAT-T", "ESP", "TLS", "junos-ping"}

# Define zone names considered "management" zones
MANAGEMENT_ZONE_CANDIDATES = {"GRAY_MGMT", "gray-mgmt", "MGMT", "gray_mgmt", "gray-mgmt-services"}

@pytest.mark.metadata({
    "requirement_id": "EG-FW-6",
    "title": "Remote admin protocols must be restricted to SSHv2, IPsec, or TLS",
    "requires_context": True,
    "related_config_keys": [
        "junos:configuration.system.services.ssh",
        "junos:configuration.security.policies",
        "junos:configuration.security.zones"
    ]
})
@pytest.mark.eg_fw_6
def test_remote_admin_protocols_are_restricted(junos_config: Dict[str, Any],
                                               expected_values: Dict[str, Any],
                                               device_name: str):
    """
    Validates EG-FW-6: Remote admin protocols from the Gray Management Network and EG Networks
    must be restricted to SSHv2, IPsec, or TLS only.
    """
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to Junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")

    # Step 1: Validate SSH version is explicitly configured to v2
    ssh_config = junos_config.get("system", {}).get("services", {}).get("ssh", {})
    ssh_versions = ssh_config.get("protocol-version", [])
    assert "v2" in ssh_versions, f"{REQUIREMENT_6} — SSHv2 is not explicitly enabled on {device_name}"

    # Step 2: Determine allowed admin applications
    allowed_admin_apps: Set[str] = set(expected_values.get("allowed_remote_admin_protocols", []))
    if not allowed_admin_apps:
        allowed_admin_apps = DEFAULT_ALLOWED_ADMIN_PROTOCOLS

    # Step 3: Check security policies from management zones to SELF
    unauthorized_apps_found = []

    for mgmt_zone in MANAGEMENT_ZONE_CANDIDATES:
        policies = get_security_policies(junos_config, from_zone=mgmt_zone, to_zone="SELF")
        for policy in policies:
            for term in get_policy_terms(policy):
                if "permit" not in term.get("then", {}):
                    continue  # Only check permitted terms
                apps = term.get("match", {}).get("application", [])
                for app in apps:
                    if app not in allowed_admin_apps:
                        unauthorized_apps_found.append(f"{mgmt_zone} → SELF: {app}")

    # Step 4: Assert all permitted apps are compliant
    assert not unauthorized_apps_found, (
        f"{REQUIREMENT_6} — Unauthorized admin protocols allowed: {', '.join(unauthorized_apps_found)}"
    )
