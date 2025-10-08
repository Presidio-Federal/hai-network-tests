import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.firewall import should_test_device, get_interface_filter, extract_firewall_filter

REQUIREMENT_12 = "EG-FW-12: Inward interface filter must deny unmatched traffic"

@pytest.mark.metadata({
    "requirement_id": "EG-FW-12",
    "title": "Inward interface filter must deny unmatched traffic",
    "requires_context": False,
    "related_config_keys": [
        "junos:configuration.interfaces.interface",
        "junos:configuration.firewall.family.inet.filter"
    ]
})
@pytest.mark.eg_fw_12
def test_inward_interface_denies_unmatched_traffic(device_config, expected_values):
    """Validates EG-FW-12: Inward interface filter denies unmatched traffic."""
    # Skip test if not applicable to this device
    if not should_test_device(expected_values, required_device_type="gray_firewall", required_platform="junos"):
        pytest.skip(f"Test only applies to junos gray_firewall devices, this is a {expected_values.get('platform')} {expected_values.get('device_type')} device")
        
    config = device_config["mdd_data"]["config"]["junos:configuration"]

    # Step 1: Identify the inward interface (ge-0/0/1) and its input filter
    interfaces = config["interfaces"]["interface"]
    inward_interface = next((iface for iface in interfaces if iface["name"] == "ge-0/0/1"), None)
    assert inward_interface, f"{REQUIREMENT_12} — Inward interface 'ge-0/0/1' not found"

    units = inward_interface.get("unit", [])
    assert units, f"{REQUIREMENT_12} — No unit defined for 'ge-0/0/1'"
    unit = units[0]
    inet = unit.get("family", {}).get("inet", {})
    input_filter = inet.get("filter", {}).get("input", {}).get("filter-name")
    assert input_filter, f"{REQUIREMENT_12} — No input filter on 'ge-0/0/1'"

    # Step 2: Locate the filter
    filters = config["firewall"]["family"]["inet"]["filter"]
    matching_filter = next((f for f in filters if f["name"] == input_filter), None)
    assert matching_filter, f"{REQUIREMENT_12} — Filter '{input_filter}' not found"

    # Step 3: Validate the filter has terms
    terms = matching_filter.get("term", [])
    assert terms, f"{REQUIREMENT_12} — No terms in filter '{input_filter}'"

    # Step 4: Confirm the last term is a discard or deny
    last_term = terms[-1]
    term_name = last_term.get("name", "unknown")
    assert "then" in last_term, f"{REQUIREMENT_12} — Final term '{term_name}' in filter '{input_filter}' missing 'then' block"
    then_clause = last_term["then"]
    assert "discard" in then_clause or "deny" in then_clause or then_clause == {"discard": {}}, (
        f"{REQUIREMENT_12} — Final term '{term_name}' in filter '{input_filter}' does not deny traffic (then: {then_clause})"
    )