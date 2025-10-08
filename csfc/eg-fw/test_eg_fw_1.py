import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

import pytest
from tests.helpers.firewall import (
    get_security_policies,
    get_policy_terms,
    should_test_device
)

REQUIREMENT_1 = "EG-FW-1: Only known gray IPs and management traffic are accepted"

@pytest.mark.eg_fw_1
def test_all_sources_and_protocols_are_allowed(junos_config, expected_values, device_name):
    """Validates EG-FW-1: Only expected gray IPs and management traffic are accepted via security policies"""

    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices")

    if not junos_config:
        pytest.skip(f"Device {device_name} has no Junos configuration")

    # 👇 Debug to confirm keys
    print(f"\nDEBUG: expected_values keys = {expected_values.keys()}")
    
    # Look for address_book directly in expected_values instead of through global_services
    address_book = expected_values.get("address_book")

    if not address_book:
        pytest.skip(f"{REQUIREMENT_1} — No address book entries found under expected_values['address_book']")

    name_to_prefix = {
        entry["name"]: entry["ip-prefix"]
        for entry in address_book
        if "name" in entry and "ip-prefix" in entry
    }

    expected_sources = set(name_to_prefix.values())

    gray_policies = get_security_policies(junos_config, from_zone="GRAY_SERVICES")
    if not gray_policies:
        gray_policies = get_security_policies(junos_config, from_zone="GRAY-MGMT")
    if not gray_policies:
        pytest.skip(f"No applicable security policies found for {device_name} from GRAY_SERVICES or GRAY-MGMT")

    actual_sources = set()
    for policy in gray_policies:
        for term in get_policy_terms(policy):
            match = term.get("match", {})
            for addr in match.get("source-address", []):
                ip = name_to_prefix.get(addr, addr)
                actual_sources.add(ip)

    unmatched = actual_sources - expected_sources
    assert unmatched == set(), (
        f"{REQUIREMENT_1} — Unexpected source addresses found: {unmatched}"
    )
