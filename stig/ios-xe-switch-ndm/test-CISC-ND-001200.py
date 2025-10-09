"""
STIG ID: CISC-ND-001200
Rule ID: SV-215844r961554_rule
Severity: High
Finding ID: V-215844

Description:
The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) 
to protect the integrity of remote maintenance sessions.

NOTE: Although allowed by SP800-131Ar2 for some applications, SHA-1 is considered a compromised 
hashing standard and is being phased out of use by industry and Government standards. 
Unless required for legacy use, DoD systems should not be configured to use SHA-1 for 
integrity of remote access sessions.

Check Content:
Review the Cisco router configuration to determine whether FIPS-validated HMAC is enabled.

Step 1: Verify the router is using SSH version 2.

router#show running-config | include ip ssh version
ip ssh version 2

If "ip ssh version 2" is not found, this is a finding.

Step 2: Verify the SSH server is using FIPS-validated HMAC algorithms.

router#show running-config | include ip ssh server algorithm mac
ip ssh server algorithm mac hmac-sha2-256

If the router is not configured to use FIPS-validated HMAC (such as hmac-sha2-256, hmac-sha2-512) 
to protect the integrity of remote maintenance sessions, this is a finding.

Fix Text:
Step 1: Configure the router to use SSH version 2.

router#conf t
router(config)#ip ssh version 2
router(config)#end
router#write memory

Step 2: Configure the SSH server to use FIPS-validated HMAC algorithms.

router#conf t
router(config)#ip ssh server algorithm mac hmac-sha2-256
router(config)#end
router#write memory
"""

import json
import os
import pytest
import re

TEST_DESCRIPTION = "Validate FIPS-validated HMAC for remote maintenance sessions"
TEST_ID = "CISC-ND-001200"
TEST_SEVERITY = "High"
TEST_FINDING_ID = "V-215844"

def test_fips_hmac_remote_sessions():
    """
    Test to validate that the router is configured to use FIPS-validated HMAC
    to protect the integrity of remote maintenance sessions.
    
    STIG ID: CISC-ND-001200
    Rule ID: SV-215844r961554_rule
    Severity: High
    Finding ID: V-215844
    
    Checks:
    1. Verify SSH version 2 is configured
    2. Verify FIPS-validated HMAC algorithms (hmac-sha2-256, hmac-sha2-512) are configured
    """
    # Load device configurations from the test input
    test_input_file = os.environ.get('TEST_INPUT_JSON', 'test_input.json')
    with open(test_input_file, 'r') as f:
        test_input = json.load(f)
    
    # List of FIPS-validated HMAC algorithms
    fips_hmac_algorithms = ['hmac-sha2-256', 'hmac-sha2-512']
    
    # Process each device in the test input
    for device in test_input.get('devices', []):
        device_name = device.get('name', 'Unknown Device')
        running_config = device.get('running_config', '')
        
        # Check 1: Verify SSH version 2 is configured
        ssh_version_configured = False
        for line in running_config.splitlines():
            if 'ip ssh version 2' in line:
                ssh_version_configured = True
                break
        
        assert ssh_version_configured, f"Device {device_name}: 'ip ssh version 2' must be configured"
        
        # Check 2: Verify FIPS-validated HMAC algorithms are configured
        hmac_algorithm_configured = False
        configured_algorithms = []
        
        for line in running_config.splitlines():
            if 'ip ssh server algorithm mac' in line:
                # Extract the configured MAC algorithms
                match = re.search(r'ip ssh server algorithm mac\s+(.+)$', line)
                if match:
                    configured_algorithms = match.group(1).split()
                    
                    # Check if any of the configured algorithms are FIPS-validated
                    for algorithm in configured_algorithms:
                        if algorithm in fips_hmac_algorithms:
                            hmac_algorithm_configured = True
                            break
        
        # Provide detailed error message if no FIPS algorithms are found
        if not hmac_algorithm_configured:
            if configured_algorithms:
                error_message = f"Device {device_name}: No FIPS-validated HMAC algorithms found. Configured: {configured_algorithms}. Must use at least one of: {fips_hmac_algorithms}"
            else:
                error_message = f"Device {device_name}: No SSH MAC algorithms configured. Must configure at least one FIPS-validated algorithm: {fips_hmac_algorithms}"
            
            assert False, error_message
        
        # Check 3: Verify no weak algorithms are configured alongside FIPS algorithms
        weak_algorithms = ['hmac-sha1', 'hmac-md5']
        weak_algorithms_found = [algo for algo in configured_algorithms if algo in weak_algorithms]
        
        if weak_algorithms_found:
            assert False, f"Device {device_name}: Weak MAC algorithms detected: {weak_algorithms_found}. Remove these and use only FIPS-validated algorithms."