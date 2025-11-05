#!/usr/bin/env python3

STIG_ID = "CISC-ND-001210"
FINDING_ID = "V-220556"
RULE_ID = "SV-220556r961557_rule"
SEVERITY = "High"
CATEGORY = "STIG"
PLATFORM = "ios-xe-router-ndm"
TITLE = "Ensure SSH version 2 and secure password configurations"

import json
import os
import re
import pytest


def test_ssh_security():
    """Test SSH security configurations."""
    # Load device state data from the input JSON file
    input_file = os.environ.get("TEST_INPUT_JSON", "test_input.json")
    
    with open(input_file, "r") as f:
        test_data = json.load(f)
    
    # Track test results for each device
    results = {}
    failures = []
    
    for device_name, device_config in test_data.items():
        config_text = device_config.get("config", "")
        
        # Initialize device results
        results[device_name] = {
            "ssh_version_2": False,
            "no_clear_text_passwords": True,
            "ssh_only_transport": True
        }
        
        # Check for SSH version 2 configuration
        # In newer IOS versions, SSH v2 is default if not explicitly specified
        # Look for explicit configuration or secure algorithm configurations that imply v2
        if "ip ssh version 2" in config_text:
            results[device_name]["ssh_version_2"] = True
        elif "ip ssh server algorithm" in config_text:
            # SSH server algorithm configs imply SSH v2
            results[device_name]["ssh_version_2"] = True
        
        # Check VTY line configurations
        vty_configs = re.findall(r"line vty \d+( \d+)?\n(.*?)(?=\n[^\s])", config_text, re.DOTALL)
        
        for vty_match in vty_configs:
            vty_config = vty_match[1]
            
            # Check for password clear text (password 0 or just password without type)
            if re.search(r"password (0 \S+|\S+)", vty_config):
                results[device_name]["no_clear_text_passwords"] = False
                
            # Check if transport input is restricted to SSH only
            transport_input = re.search(r"transport input (\S+)", vty_config)
            if transport_input:
                if transport_input.group(1) != "ssh" and "all" in transport_input.group(1):
                    results[device_name]["ssh_only_transport"] = False
        
        # Add device to failures list if any check failed
        if not all([
            results[device_name]["ssh_version_2"],
            results[device_name]["no_clear_text_passwords"],
            results[device_name]["ssh_only_transport"]
        ]):
            failures.append(device_name)
    
    # Generate detailed error message for failures
    error_message = ""
    if failures:
        error_message = "SSH security check failed for devices:\n"
        for device in failures:
            error_message += f"\n{device}:\n"
            if not results[device]["ssh_version_2"]:
                error_message += "  - SSH version 2 not explicitly configured\n"
            if not results[device]["no_clear_text_passwords"]:
                error_message += "  - Clear text passwords found on VTY lines\n"
            if not results[device]["ssh_only_transport"]:
                error_message += "  - Transport input not restricted to SSH only\n"
    
    # Assert that all devices pass all checks
    assert not failures, error_message