import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.firewall import get_security_policies, get_policy_terms, extract_address_sets, should_test_device

REQUIREMENT_2 = "EG-FW-2: Only permit packets between Encryption Component interfaces"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-2",
    "title": "Only permit packets between Encryption Component interfaces",
    "requires_context": False,
    "related_config_keys": [
        "junos:configuration.security.policies",
        "junos:configuration.security.zones",
        "junos:configuration.interfaces"
    ]
})

@pytest.mark.eg_fw_2
def test_only_allows_encryption_component_interfaces(junos_config, expected_values):
    """Validates EG-FW-2: Only permits packets between Encryption Component interfaces"""
    # Skip test if not applicable to this device
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")
        
    # Expected Encryption Component interfaces
    expected_interfaces = {
        "INNER-ENCRYPT-GRAY",  # 10.160.0.5 (HQ-INNER-FIREWALL inside interface)
        "INNER-ENCRYPT-RED",   # 10.160.0.6 (HQ-SECRET-RTR external interface)
        "OUTER-ENCRYPT",       # 10.160.0.1 (HQ-GRAY-ROUTER external interface)
        "BRANCH-RED-FW"        # 10.170.0.6 (BRANCH-RED-FW external interface)
    }

    # Get relevant policies (INSIDE to OUTSIDE and OUTSIDE to INSIDE)
    inside_to_outside = get_security_policies(junos_config, from_zone="INSIDE", to_zone="OUTSIDE")
    outside_to_inside = get_security_policies(junos_config, from_zone="OUTSIDE", to_zone="INSIDE")
    relevant_policies = inside_to_outside + outside_to_inside
    
    assert len(relevant_policies) > 0, f"{REQUIREMENT_2} — No policies found between INSIDE and OUTSIDE zones"

    # Validate each policy
    for policy in relevant_policies:
        direction = f"{policy['from-zone-name']} to {policy['to-zone-name']}"
        
        # Get policy terms
        terms = get_policy_terms(policy)
        
        for term in terms:
            term_name = term["name"]
            # Skip terms that do not permit traffic
            if "permit" not in term["then"]:
                continue

            # Validate that source-address and destination-address are defined
            from_block = term.get("match", {})
            assert "source-address" in from_block, (
                f"{REQUIREMENT_2} — Missing source-address in term '{term_name}' ({direction})"
            )
            assert "destination-address" in from_block, (
                f"{REQUIREMENT_2} — Missing destination-address in term '{term_name}' ({direction})"
            )

            # Extract and validate source addresses
            sources = set(from_block["source-address"])
            assert sources.issubset(expected_interfaces), (
                f"{REQUIREMENT_2} — Unexpected source addresses in term '{term_name}' ({direction}): "
                f"{sources} (expected subset of {expected_interfaces})"
            )

            # Extract and validate destination addresses
            destinations = set(from_block["destination-address"])
            assert destinations.issubset(expected_interfaces), (
                f"{REQUIREMENT_2} — Unexpected destination addresses in term '{term_name}' ({direction}): "
                f"{destinations} (expected subset of {expected_interfaces})"
            )

            # Validate applications (e.g., IKE, ESP for IPsec)
            applications = set(from_block.get("application", []))
            allowed_applications = {"any", "IKE", "ESP", "IKE-NAT-T", "junos-ping"}
            assert applications.issubset(allowed_applications), (
                f"{REQUIREMENT_2} — Unexpected applications in term '{term_name}' ({direction}): "
                f"{applications} (expected subset of {allowed_applications})"
            )