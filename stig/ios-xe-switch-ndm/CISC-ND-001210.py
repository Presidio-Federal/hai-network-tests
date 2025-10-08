"""
STIG ID: CISC-ND-001210
Finding ID: V-220556
Severity: High
STIG Title: Cisco IOS XE Switch NDM — Use Secure Protocols for Remote Access
Date: 2025-02-20
Source: DISA Cisco IOS XE Switch NDM STIG
Check Text:
Verify SSH version 2 and FIPS-approved encryption algorithms are configured.

Fix Text:
Configure the Cisco switch to implement cryptographic mechanisms to protect the confidentiality
of remote maintenance sessions using FIPS 140-2 approved algorithms.
"""

import os
import json
import pytest

STIG_ID = "CISC-ND-001210"
FINDING_ID = "V-220556"
RULE_ID = "SV-220556r961557_rule"
SEVERITY = "High"
CATEGORY = "STIG"
PLATFORM = "ios-xe-switch-ndm"
TITLE = "Ensure SSH and FIPS-approved encryption algorithms are configured"


@pytest.mark.stig
@pytest.mark.iosxe
def test_secure_protocols_configured():
    """
    Test that SSH version 2 and FIPS-approved encryption algorithms
    are configured on Cisco IOS XE devices.
    """

    # Load state file provided via FastMCP / Pytest container
    state_path = os.getenv("TEST_INPUT_JSON", "/tmp/pytest_state.json")
    with open(state_path) as f:
        state = json.load(f)

    devices = state.get("devices", [])
    assert devices, "No devices found in test state"

    for device in devices:
        if device.get("type", "").lower() not in ["cisco_iosxe", "iosxe", "ios-xe"]:
            pytest.skip(f"Skipping non-IOS-XE device: {device.get('name')}")

        # Simulated configuration data location
        config = device.get("config", {})
        ssh_config = config.get("ssh", {})

        # --- Requirement 1: SSH version 2 ---
        ssh_version = ssh_config.get("version")
        assert ssh_version == 2, f"{device['name']}: SSH version {ssh_version} is not 2"

        # --- Requirement 2: FIPS-approved algorithms ---
        valid_algorithms = {"aes256-ctr", "aes192-ctr", "aes128-ctr"}
        configured_algorithms = set(ssh_config.get("encryption_algorithms", []))
        missing = valid_algorithms - configured_algorithms
        assert not missing, (
            f"{device['name']}: Missing required SSH encryption algorithms: {missing}"
        )

        # --- Requirement 3 (optional future check): no insecure services ---
        insecure_services = []
        if config.get("services", {}).get("telnet", False):
            insecure_services.append("telnet")
        if config.get("services", {}).get("http", False):
            insecure_services.append("http")

        assert not insecure_services, (
            f"{device['name']}: Insecure services enabled: {insecure_services}"
        )
