#!/usr/bin/env python3
"""
Test for STIG ID: CISC-ND-000620
"""

import os
import json
import pytest

STIG_ID = "CISC-ND-000620"
FINDING_ID = "V-215687"
RULE_ID = "SV-215687r991830_rule"
SEVERITY = "High"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router-ndm"
TITLE = "The Cisco router must only store cryptographic representations of passwords"

def test_password_encryption_enabled():
    """
    Test that password encryption is enabled on all devices.
    
    STIG V-215687 (CISC-ND-000620) requires that Cisco routers must only store
    cryptographic representations of passwords. This is validated by checking
    for the presence of the "password-encryption" service in the configuration.
    """
    # Get the path to the test input file
    test_input_json = os.environ.get('TEST_INPUT_JSON', None)
    
    # If TEST_INPUT_JSON environment variable is set, use it
    if test_input_json and os.path.exists(test_input_json):
        with open(test_input_json, 'r') as f:
            devices = json.load(f)
    else:
        # Otherwise, look for device configs in the config directory
        config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config')
        devices = {}
        
        for filename in os.listdir(config_dir):
            if filename.endswith('.json'):
                device_name = filename.split('.')[0]
                with open(os.path.join(config_dir, filename), 'r') as f:
                    try:
                        devices[device_name] = json.load(f)
                    except json.JSONDecodeError:
                        print(f"Error: Could not parse {filename} as JSON")
    
    # Dictionary to store results
    results = {}
    
    # Check each device configuration
    for device_name, config in devices.items():
        try:
            # Check if password encryption is enabled
            # Path: tailf-ncs:config -> tailf-ned-cisco-ios:service -> password-encryption
            service_config = config.get('tailf-ncs:config', {}).get('tailf-ned-cisco-ios:service', {})
            password_encryption_enabled = 'password-encryption' in service_config
            
            results[device_name] = {
                'password_encryption_enabled': password_encryption_enabled,
                'compliant': password_encryption_enabled
            }
            
            # Assert that password encryption is enabled
            assert password_encryption_enabled, f"Password encryption is not enabled on {device_name}"
            
        except (KeyError, AttributeError) as e:
            results[device_name] = {
                'error': str(e),
                'compliant': False
            }
            assert False, f"Error checking password encryption on {device_name}: {e}"
    
    # Print summary
    print("\nSTIG Compliance Summary:")
    print(f"STIG ID: {STIG_ID}")
    print(f"Finding ID: {FINDING_ID}")
    print(f"Rule ID: {RULE_ID}")
    print(f"Title: {TITLE}")
    print("\nDevice Results:")
    
    for device, result in results.items():
        status = "PASS" if result.get('compliant') else "FAIL"
        print(f"{device}: {status}")
        if not result.get('compliant'):
            if 'error' in result:
                print(f"  Error: {result['error']}")
            else:
                print("  Password encryption service is not enabled")

if __name__ == "__main__":
    test_password_encryption_enabled()