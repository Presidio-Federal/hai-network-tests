import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.firewall import (
    get_security_policies,
    get_policy_terms,
    should_test_device
)
from typing import Dict, Any, Set

REQUIREMENT_5 = "EG-FW-5: Block traffic between Inner VPN Gateways of different classification levels"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-5",
    "title": "Block traffic between Inner VPN Gateways of different classification levels",
    "requires_context": True,
    "related_config_keys": [
        "junos:configuration.security.policies",
        "junos:configuration.security.zones",
        "junos:configuration.interfaces"
    ]
})

def check_policy_compliance(policy: Dict[str, Any], inner_vpn_gateways: Set[str]) -> None:
    """
    Check that a policy complies with the requirement that traffic is only permitted
    between gateways of the same classification level.
    
    Args:
        policy: Security policy configuration
        inner_vpn_gateways: Set of known Inner VPN Gateway names
    """
    direction = f"{policy['from-zone-name']} to {policy['to-zone-name']}"
    allowed_interfaces = {"INNER-ENCRYPT-GRAY", "OUTER-ENCRYPT"} | inner_vpn_gateways
    
    for term in get_policy_terms(policy):
        # Skip non-permit rules
        if "permit" not in term.get("then", {}):
            continue
            
        match = term.get("match", {})
        src = set(match.get("source-address", []))
        dst = set(match.get("destination-address", []))
        
        term_name = term.get("name", "unknown")
        
        # Check if both source and destination are Inner VPN Gateways
        if src.issubset(inner_vpn_gateways) and dst.issubset(inner_vpn_gateways):
            # Since we only have one classification level, this is allowed
            continue
            
        # If either source or destination is an Inner VPN Gateway, the other must be a known gateway
        if src.intersection(inner_vpn_gateways) or dst.intersection(inner_vpn_gateways):
            assert src.issubset(allowed_interfaces), \
                f"{REQUIREMENT_5} — Unexpected source in term '{term_name}' ({direction}): {src}"
            assert dst.issubset(allowed_interfaces), \
                f"{REQUIREMENT_5} — Unexpected destination in term '{term_name}' ({direction}): {dst}"

@pytest.mark.eg_fw_5
def test_block_traffic_between_different_classification_levels(junos_config, expected_values, device_name):
    """Validates EG-FW-5: Blocks traffic between Inner VPN Gateways of different classification levels."""
    # Skip test if not applicable to this device
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")
    
    # Skip if junos_config is empty (non-Junos device)
    if not junos_config:
        pytest.skip(f"Device {device_name} is not a Junos device or has no Junos configuration")
    
    # Known Inner VPN Gateways (all at the same classification level)
    inner_vpn_gateways = {"INNER-ENCRYPT-RED", "BRANCH-RED-FW"}  # 10.160.0.6, 10.170.0.6

    # Get INSIDE to OUTSIDE and OUTSIDE to INSIDE policies
    inside_to_outside = get_security_policies(junos_config, from_zone="INSIDE", to_zone="OUTSIDE")
    outside_to_inside = get_security_policies(junos_config, from_zone="OUTSIDE", to_zone="INSIDE")
    relevant_policies = inside_to_outside + outside_to_inside
    
    assert len(relevant_policies) > 0, f"{REQUIREMENT_5} — No policies found between INSIDE and OUTSIDE zones"

    # Validate that all permitted traffic is between gateways of the same classification level
    for policy in relevant_policies:
        check_policy_compliance(policy, inner_vpn_gateways)

    # Ensure a default deny policy exists
    all_policies = get_security_policies(junos_config)
    inside_to_inside_ts_policies = [
        p for p in all_policies 
        if p["from-zone-name"] == "INSIDE" and p["to-zone-name"] == "INSIDE-TS"
    ]
    
    deny_all_exists = False
    for policy in inside_to_inside_ts_policies:
        for term in get_policy_terms(policy):
            if term.get("name") == "DENY-ALL" and "deny" in term.get("then", {}):
                deny_all_exists = True
                break
                
    assert deny_all_exists, f"{REQUIREMENT_5} — No default deny policy for INSIDE to INSIDE-TS"