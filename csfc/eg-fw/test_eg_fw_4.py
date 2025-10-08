import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.firewall import (
    extract_firewall_filter,
    get_interface_filter,
    check_final_term_discard,
    should_test_device
)
from tests.helpers.validator import FirewallValidator, perform_validation

REQUIREMENT_4 = "EG-FW-4: Outward interface filter must deny unmatched traffic"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-4",
    "title": "Outward interface filter must deny unmatched traffic",
    "requires_context": False,
    "related_config_keys": [
        "junos:configuration.interfaces",
        "junos:configuration.firewall.family.inet.filter"
    ]
})

@pytest.mark.eg_fw_4
def test_outward_interface_denies_unmatched_traffic(junos_config, expected_values, device_name, device_config):
    """
    Validates EG-FW-4: The Gray Firewall must deny all traffic on the outward interface
    (ge-0/0/0) that is not explicitly allowed.
    
    This test is implemented using both the original approach and the new validator framework.
    """
    # Skip test if not applicable to this device
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")
    
    # Skip if junos_config is empty (non-Junos device)
    if not junos_config:
        pytest.skip(f"Device {device_name} is not a Junos device or has no Junos configuration")
    
    # APPROACH 1: Original implementation
    # Step 1: Get the filter applied to the outward interface (ge-0/0/0)
    outward_interface = "ge-0/0/0"  # Gray firewall outward interface
    
    input_filter = get_interface_filter(junos_config, outward_interface)
    assert input_filter is not None, (
        f"{REQUIREMENT_4} — Interface '{outward_interface}' not found or missing inet filter configuration"
    )
    
    # Step 2: Extract the filter configuration
    try:
        filter_obj = extract_firewall_filter(junos_config, input_filter)
    except:
        pytest.fail(f"{REQUIREMENT_4} — Filter '{input_filter}' not found in configuration")
    
    # Step 3: Check that the final term denies unmatched traffic
    assert check_final_term_discard(filter_obj), (
        f"{REQUIREMENT_4} — Final term in filter '{input_filter}' does not deny unmatched traffic"
    )
    
    # APPROACH 2: Using the new validator framework
    validator = FirewallValidator(device_config, expected_values, device_name)
    validator.set_requirement(REQUIREMENT_4)
    
    # Step 1: Validate that the interface exists and has a filter
    result = validator.validate_interface_filter("ge-0/0/0", input_filter)
    perform_validation(lambda: result, REQUIREMENT_4)
    
    # Step 2: Validate that the filter denies unmatched traffic
    result = validator.validate_filter_denies_unmatched(input_filter)
    perform_validation(lambda: result, REQUIREMENT_4)