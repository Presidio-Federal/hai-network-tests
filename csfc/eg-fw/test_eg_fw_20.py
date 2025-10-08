import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.firewall import should_test_device

REQUIREMENT_20 = "EG-FW-20: Gray Firewall must not permit split-tunneling"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-20",
    "title": "Gray Firewall must not permit split-tunneling",
    "requires_context": True,
    "related_config_keys": [
        "junos:configuration.routing-options.static.route",
        "junos:configuration.security.policies.policy"
    ]
})
@pytest.mark.eg_fw_20
def test_no_split_tunneling(device_config, expected_values):
    """Validates EG-FW-20: Gray Firewall does not permit split-tunneling."""
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices")

    config = device_config["mdd_data"]["config"]["junos:configuration"]

    # Step 1: Get the expected Outer Encryption Component address
    device_name = config["system"]["host-name"]
    outer_encryption_component = expected_values.get("outer_encryption_component")
    assert outer_encryption_component, f"{REQUIREMENT_20} — No outer_encryption_component defined for {device_name} in expected-values.yml"

    # Step 2: Check routing (default route must point to Outer Encryption Component)
    routes = config.get("routing-options", {}).get("static", {}).get("route", [])
    default_route = next((r for r in routes if r["name"] == "0.0.0.0/0"), None)
    assert default_route, f"{REQUIREMENT_20} — No default route defined"
    assert default_route["next-hop"] == [outer_encryption_component], (
        f"{REQUIREMENT_20} — Default route does not point to Outer Encryption Component ({outer_encryption_component})"
    )

    # Step 3: Check policies (no traffic should bypass the tunnel)
    policies = config.get("security", {}).get("policies", {}).get("policy", [])
    inside_to_outside = [p for p in policies if p["from-zone-name"] == "INSIDE" and p["to-zone-name"] == "OUTSIDE"]
    for policy in inside_to_outside:
        for rule in policy.get("policy", []):
            if "permit" not in rule["then"]:
                continue
            dst = set(rule["match"]["destination-address"])
            # Ensure traffic only goes to known Inner VPN Gateways or Outer Encryption Component
            allowed_dests = {"INNER-ENCRYPT-RED", "OUTER-ENCRYPT", "BRANCH-RED-FW"}
            assert dst.issubset(allowed_dests), f"{REQUIREMENT_20} — Policy allows traffic to bypass tunnel: {dst}"