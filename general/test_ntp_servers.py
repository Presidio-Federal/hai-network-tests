"""
NTP STIG Compliance Test

This test validates that each device has at least 2 NTP servers configured,
which is a common security requirement.
"""

import os
import sys
import json
import pytest


def load_test_data(state_file=None):
    """Load test data from the environment variable specified JSON file."""
    # Get the path to the state file from environment variable if not provided
    if state_file is None:
        state_file = os.getenv("TEST_INPUT_JSON")
    
    if not state_file:
        pytest.skip("TEST_INPUT_JSON environment variable not set")
    
    # Check if the file exists
    if not os.path.exists(state_file):
        pytest.fail(f"Test state file not found at {state_file}")
    
    # Load the JSON data
    try:
        with open(state_file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        pytest.fail(f"Invalid JSON in test state file: {state_file}")
    except Exception as e:
        pytest.fail(f"Error loading test state file: {str(e)}")


def test_ntp_server_count(state_file_path=None):
    """Test that each device has at least 2 NTP servers configured."""
    # Load the test data
    data = load_test_data(state_file_path)
    
    # Check if devices key exists
    if "devices" not in data:
        pytest.fail("No devices found in test data")
    
    devices = data["devices"]
    failed_devices = []
    
    # Check each device for NTP servers
    for device in devices:
        device_name = device.get("name", "Unknown Device")
        
        # Look for NTP servers in different possible locations in the data structure
        ntp_servers = []
        
        # Check for top-level ntp_servers array
        if "ntp_servers" in device:
            ntp_servers = device["ntp_servers"]
        
        # If not found directly, check in a services or ntp section
        elif "services" in device and not ntp_servers:
            ntp_servers = device["services"].get("ntp", {}).get("servers", [])
        
        # Check for ntp.servers array with objects that have 'address' field
        elif "ntp" in device and not ntp_servers:
            ntp_section = device["ntp"]
            if isinstance(ntp_section, dict) and "servers" in ntp_section:
                servers = ntp_section["servers"]
                # Handle both array of strings and array of objects with 'address' field
                if all(isinstance(server, dict) for server in servers):
                    ntp_servers = [server.get("address") for server in servers if "address" in server]
                else:
                    ntp_servers = servers
        
        # If still not found, check in a configuration section
        elif "config" in device and not ntp_servers:
            config = device["config"]
            if isinstance(config, dict) and "ntp" in config:
                ntp_config = config["ntp"]
                if isinstance(ntp_config, dict) and "servers" in ntp_config:
                    ntp_servers = ntp_config["servers"]
        
        # Count the NTP servers
        server_count = len(ntp_servers)
        
        # Check if there are at least 2 NTP servers
        if server_count < 2:
            failed_devices.append({
                "name": device_name,
                "ntp_server_count": server_count,
                "message": f"Device {device_name} has only {server_count} NTP server(s), minimum required is 2"
            })
    
    # If any devices failed, fail the test with details
    if failed_devices:
        failure_message = "The following devices do not have the required minimum of 2 NTP servers:\n"
        for device in failed_devices:
            failure_message += f"- {device['name']}: Found {device['ntp_server_count']} NTP server(s)\n"
        
        pytest.fail(failure_message)
