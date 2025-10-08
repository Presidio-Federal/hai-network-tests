import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))  # Add project root to path

import pytest
from tests.helpers.vpn import is_tunnel_mode_ipsec
from tests.helpers.firewall import should_test_device

REQUIREMENT = "EG-FW-21: The Gray Firewall/Encryption Component must use Tunnel mode IPsec or Transport mode IPsec with an associated tunneling protocol (e.g., GRE), authorized TLS deployment, or MACsec."

@pytest.mark.metadata({
    "requirement_id": "EG-FW-21",
    "title": "The Gray Firewall/Encryption Component must use Tunnel mode IPsec or equivalent",
    "requires_context": False,
    "related_config_keys": [
        "tailf-ned-cisco-ios:crypto.ipsec.transform-set",
        "tailf-ned-cisco-ios:interface.Tunnel"
    ]
})
@pytest.mark.eg_fw_21
def test_eg_fw_uses_tunnel_mode_ipsec(device_config, expected_values, device_name):
    """
    Validates EG-FW-21: The Gray Firewall/Encryption Component must use
    Tunnel mode IPsec or equivalent (e.g., authorized TLS, MACsec).
    """
    if not should_test_device(expected_values, required_device_type="outer_vpn", required_platform="ios"):
        pytest.skip(f"Test only applies to Cisco IOS outer_vpn devices")

    # Print debug information about the device configuration
    print(f"\nDEBUG: Device name: {device_name}")
    print(f"DEBUG: Device type: {expected_values.get('device_type')}")
    print(f"DEBUG: Platform: {expected_values.get('platform')}")
    
    # Extract configuration info
    crypto = device_config.get("mdd_data", {}).get("config", {}).get("tailf-ned-cisco-ios:crypto", {})
    transform_sets = crypto.get("ipsec", {}).get("transform-set", [])
    
    # Check for tunnel interfaces
    has_tunnel_interface = "Tunnel" in device_config.get("mdd_data", {}).get("config", {}).get("tailf-ned-cisco-ios:interface", {})
    
    # Debug output for transform sets
    print(f"DEBUG: Transform sets found: {len(transform_sets)}")
    for i, ts in enumerate(transform_sets):
        print(f"DEBUG: Transform set {i+1}: {ts}")
        print(f"DEBUG: is_tunnel_mode_ipsec: {is_tunnel_mode_ipsec(ts)}")
    
    # Check for MACsec configuration in expected_values
    has_macsec = expected_values.get("macsec_enabled", False)
    print(f"DEBUG: MACsec enabled in expected_values: {has_macsec}")
    
    # Multiple ways to satisfy the requirement
    has_tunnel_mode_ipsec = any(is_tunnel_mode_ipsec(ts) for ts in transform_sets)
    
    # The requirement can be satisfied by either tunnel mode IPsec or MACsec
    requirement_satisfied = has_tunnel_mode_ipsec or has_macsec or has_tunnel_interface
    
    assert requirement_satisfied, (
        f"{REQUIREMENT} — No compliant encryption mechanism (tunnel mode IPsec, MACsec, or GRE with IPsec) was found"
    )
