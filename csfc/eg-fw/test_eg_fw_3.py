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

REQUIREMENT_3 = "EG-FW-3: Filter on Gray Management Network interface must have a final discard term"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-3",
    "title": "Filter on Gray Management Network interface must have a final discard term",
    "requires_context": False,
    "related_config_keys": [
        "junos:configuration.interfaces",
        "junos:configuration.firewall.family.inet.filter"
    ]
})

@pytest.mark.eg_fw_3
def test_filter_has_final_discard(junos_config, expected_values, device_name):
    """Validates EG-FW-3: Filter on Gray Management Network interface has a final discard term"""
    # Skip test if not applicable to this device
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")
    
    # Skip if junos_config is empty (non-Junos device)
    if not junos_config:
        pytest.skip(f"Device {device_name} is not a Junos device or has no Junos configuration")
    
    # Validate that ge-0/0/2 has the restrict-gray-source filter
    gray_mgmt_interface = "ge-0/0/2"  # Gray management interface name
    filter_name = "restrict-gray-source"  # Expected filter name
    
    filter_input = get_interface_filter(junos_config, gray_mgmt_interface)
    assert filter_input is not None, (
        f"{REQUIREMENT_3} — Interface '{gray_mgmt_interface}' not found or missing inet filter configuration"
    )
    
    assert filter_input == filter_name, (
        f"{REQUIREMENT_3} — Interface '{gray_mgmt_interface}' does not have '{filter_name}' filter "
        f"(found: {filter_input})"
    )

    # Validate the restrict-gray-source filter
    try:
        matched_filter = extract_firewall_filter(junos_config, filter_name)
    except:
        pytest.fail(f"{REQUIREMENT_3} — Filter '{filter_name}' not found in configuration")

    # Check if final term discards unmatched traffic
    assert check_final_term_discard(matched_filter), (
        f"{REQUIREMENT_3} — Final term in filter '{filter_name}' does not discard unmatched traffic"
    )