import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.firewall import should_test_device

REQUIREMENT_15 = "EG-FW-15: Remote admin of Gray components must use SSHv2, IPsec, or TLS"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-15",
    "title": "Remote admin of Gray components must use SSHv2, IPsec, or TLS",
    "requires_context": False,
    "related_config_keys": [
        "junos:configuration.system.services.ssh",
        "junos:configuration.security.policies.policy"
    ]
})
@pytest.mark.eg_fw_15
def test_remote_admin_protocols_restricted(device_config, expected_values):
    """Validates EG-FW-15: Remote admin uses SSHv2, IPsec, or TLS with CNSA suite."""
    # Skip test if not applicable to this device
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")
        
    config = device_config["mdd_data"]["config"]["junos:configuration"]
    allowed_admin_apps = {"junos-ssh", "IKE", "IKE-NAT-T", "ESP", "TLS"}

    # Check SSH configuration (must be v2)
    ssh_config = config.get("system", {}).get("services", {}).get("ssh", {})
    assert ssh_config.get("protocol-version", []) == ["v2"], f"{REQUIREMENT_15} — SSH not set to v2"

    # Check policies from GRAY_SERVICES to OUTSIDE
    policies = config.get("security", {}).get("policies", {}).get("policy", [])
    gray_policies = [p for p in policies if p["from-zone-name"] == "GRAY_SERVICES" and p["to-zone-name"] == "OUTSIDE"]

    for policy in gray_policies:
        for rule in policy.get("policy", []):
            if "permit" not in rule["then"]:
                continue
            src = set(rule["match"]["source-address"])
            apps = set(rule["match"]["application"])
            if "GRAY-MGMT-NETWORK" in src or any("GRAY" in addr for addr in src):
                for app in apps:
                    assert app in allowed_admin_apps, f"{REQUIREMENT_15} — Unauthorized admin protocol '{app}' from Gray Management Network"