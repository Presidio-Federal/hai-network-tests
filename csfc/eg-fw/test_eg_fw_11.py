import pytest
from tests.helpers.firewall import (
    get_security_policies,
    get_policy_terms,
    should_test_device
)

REQUIREMENT = "EG-FW-11: Inward interface must block packets from unauthorized source addresses"

@pytest.mark.eg_fw_11
@pytest.mark.metadata({
    "requirement_id": "EG-FW-11",
    "title": "Inward interface must block packets from unauthorized source addresses",
    "requires_context": True,
    "related_config_keys": [
        "junos:configuration.security.policies",
        "junos:configuration.security.zones"
    ]
})
def test_inward_policy_source_address_restriction(junos_config, expected_values, device_name):
    """
    Validates EG-FW-11 using security policies instead of interface filters.
    Ensures each policy term explicitly matches source-address and is not permit-all.
    """
    # Skip if not a Junos gray firewall
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip("Test only applies to Junos gray_firewall devices")

    # Define what we consider "inward-facing" zones
    inward_zones = {"INSIDE", "SELF", "GRAY_SERVICES"}  # You can adjust this

    matched_policies = []
    missing_source_check = []

    # Print debug information about the structure of security policies
    print(f"\nDEBUG: Security policies structure in junos_config:")
    if "security" in junos_config and "policies" in junos_config["security"]:
        policies_section = junos_config["security"]["policies"]
        print(f"DEBUG: Found policies section with keys: {policies_section.keys()}")
        
        if "policy" in policies_section:
            zone_policies = policies_section["policy"]
            print(f"DEBUG: Found {len(zone_policies)} zone policies")
            
            # Loop through zone policies
            for zone_policy in zone_policies:
                from_zone = zone_policy.get("from-zone-name", "UNKNOWN")
                to_zone = zone_policy.get("to-zone-name", "UNKNOWN")
                print(f"DEBUG: Policy from zone '{from_zone}' to zone '{to_zone}'")
                
                # Check if this is an inward-facing policy
                if to_zone in inward_zones:
                    policy_entries = zone_policy.get("policy", [])
                    print(f"DEBUG: Found {len(policy_entries)} policy entries for to_zone '{to_zone}'")
                    
                    # Process each policy entry
                    for policy_entry in policy_entries:
                        policy_name = policy_entry.get("name", "UNNAMED")
                        matched_policies.append(f"{from_zone}-to-{to_zone}/{policy_name}")
                        
                        # Check if the policy has source-address restrictions
                        match = policy_entry.get("match", {})
                        then_action = policy_entry.get("then", {})
                        
                        # Only check permit policies
                        if "permit" in then_action:
                            if not match.get("source-address"):
                                missing_source_check.append(f"{from_zone}-to-{to_zone}/{policy_name}")
    else:
        print("DEBUG: No security policies found in the configuration")

    assert matched_policies, f"{REQUIREMENT} — No inward policies found targeting zones {inward_zones} on {device_name}"
    assert not missing_source_check, (
        f"{REQUIREMENT} — The following policy terms allow traffic without restricting source-address:\n"
        + "\n".join(missing_source_check)
    )
