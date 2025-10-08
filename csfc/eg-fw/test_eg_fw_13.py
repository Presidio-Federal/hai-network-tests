import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.firewall import should_test_device

REQUIREMENT_13 = "EG-FW-13: Allow control plane traffic between Gray components"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-13",
    "title": "Allow control plane traffic between Gray components",
    "requires_context": False,
    "related_config_keys": [
        "junos:configuration.security.policies.policy",
        "junos:configuration.firewall.family.inet.filter"
    ]
})
@pytest.mark.eg_fw_13
def test_control_plane_traffic_allowed(device_config, expected_values):
    """Validates EG-FW-13: Allows control plane traffic (NTP, DHCP, DNS) between Gray components."""
    # Skip test if not applicable to this device
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")
        
    # Allowed control plane protocols
    allowed_apps = {"junos-ntp", "junos-dhcp-client", "junos-dhcp-server", "junos-dns-udp"}

    # Ensure the config has the expected structure
    try:
        config = device_config["mdd_data"]["config"]["junos:configuration"]
        security = config.get("security", {})
        policies = security.get("policies", {}).get("policy", [])
    except (KeyError, TypeError) as e:
        pytest.fail(f"{REQUIREMENT_13} — Error accessing configuration: {str(e)}")
        return

    # Check policies from GRAY_SERVICES to OUTSIDE
    gray_policies = [p for p in policies if p.get("from-zone-name") == "GRAY_SERVICES" and p.get("to-zone-name") == "OUTSIDE"]

    if not gray_policies:
        pytest.fail(f"{REQUIREMENT_13} — No policies found from GRAY_SERVICES to OUTSIDE")
        return

    # Validate that control plane traffic is allowed
    control_plane_allowed = False
    for policy in gray_policies:
        for rule in policy.get("policy", []):
            if "permit" not in rule.get("then", {}):
                continue
                
            match = rule.get("match", {})
            src = set(match.get("source-address", []))
            dst = set(match.get("destination-address", []))
            apps = set(match.get("application", []))
            
            # Check if the rule allows traffic from Gray Management Network to Outer Encryption Component
            if "GRAY-MGMT-NETWORK" in src and "OUTER-ENCRYPT" in dst:
                if apps.intersection(allowed_apps) or "any" in apps:
                    control_plane_allowed = True
                    break
        if control_plane_allowed:
            break

    assert control_plane_allowed, f"{REQUIREMENT_13} — No control plane traffic (NTP, DHCP, DNS) allowed from Gray Management Network to Outer Encryption Component"

    # Check filter on ge-0/0/2 for Gray Management Network
    try:
        firewall = config.get("firewall", {})
        family = firewall.get("family", {})
        inet = family.get("inet", {})
        filters = inet.get("filter", [])
    except (KeyError, TypeError) as e:
        pytest.fail(f"{REQUIREMENT_13} — Error accessing firewall configuration: {str(e)}")
        return

    gray_filter = next((f for f in filters if f.get("name") == "restrict-gray-source"), None)
    assert gray_filter, f"{REQUIREMENT_13} — Filter 'restrict-gray-source' not found"

    filter_apps = set()
    for term in gray_filter.get("term", []):
        if "accept" not in term.get("then", {}):
            continue
        from_clause = term.get("from", {})
        proto = from_clause.get("protocol", [None])[0]
        port = from_clause.get("destination-port", [None])[0]
        if proto and port:
            filter_apps.add(f"{proto}/{port}")

    required_apps = {"udp/123", "udp/67", "udp/68", "udp/53"}
    assert filter_apps.issuperset(required_apps), f"{REQUIREMENT_13} — Filter 'restrict-gray-source' does not allow all required control plane protocols: {required_apps - filter_apps}"