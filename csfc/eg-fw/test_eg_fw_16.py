import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.firewall import should_test_device

REQUIREMENT_16 = "EG-FW-16: Double encryption for Gray Management traffic"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-16",
    "title": "Double encryption for Gray Management traffic",
    "requires_context": True,
    "related_config_keys": [
        "junos:configuration.system.services.ssh",
        "junos:configuration.security.policies.policy"
    ]
})
@pytest.mark.eg_fw_16
def test_double_encryption_for_management_traffic(device_config, expected_values):
    """Validates EG-FW-16: Double encryption for Gray Management traffic."""
    # Skip test if not applicable to this device
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")
        
    config = device_config["mdd_data"]["config"]["junos:configuration"]
    allowed_admin_apps = {"junos-ssh", "IKE", "IKE-NAT-T", "ESP", "TLS"}

    # Step 1: Validate inner layer (Gray Firewall uses SSHv2, IPsec, or TLS)
    ssh_config = config.get("system", {}).get("services", {}).get("ssh", {})
    assert ssh_config.get("protocol-version", []) == ["v2"], f"{REQUIREMENT_16} — SSH not set to v2"

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
                    assert app in allowed_admin_apps, f"{REQUIREMENT_16} — Unauthorized inner admin protocol '{app}' from Gray Management Network"

    # Step 2: Validate outer layer (Outer Encryption Component uses IPsec)
    # Since we don't have HQ-GRAY-ROUTER's config, we'll check policies for IPsec traffic to OUTER-ENCRYPT
    ipsec_allowed = False
    for policy in gray_policies:
        for rule in policy.get("policy", []):
            if "permit" not in rule["then"]:
                continue
            dst = set(rule["match"]["destination-address"])
            apps = set(rule["match"]["application"])
            if "OUTER-ENCRYPT" in dst and any(app in {"IKE", "ESP"} for app in apps):
                ipsec_allowed = True
                break
        if ipsec_allowed:
            break
    assert ipsec_allowed, f"{REQUIREMENT_16} — No IPsec allowed to Outer Encryption Component for outer layer encryption"