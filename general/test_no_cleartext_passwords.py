"""
Test to validate that no cleartext passwords are present in device configurations.

This test checks for various forms of cleartext password configurations that might be present
in network device configurations, including:
- Unencrypted password configurations
- Service password configurations without encryption
- SNMP community strings
- Plaintext authentication in routing protocols
- Other common patterns where passwords might be stored in cleartext
"""

import json
import os
import pytest
import re

TEST_DESCRIPTION = "Validate no cleartext passwords in configurations"

def test_no_cleartext_passwords():
    """
    Test to validate that no cleartext passwords are present in device configurations.
    
    This test checks for:
    1. Unencrypted line passwords (console, vty, aux)
    2. Enable passwords without encryption
    3. Username passwords without encryption
    4. SNMP community strings
    5. Plaintext authentication in routing protocols
    6. Other service passwords without proper encryption
    
    The test ensures that all password configurations use appropriate encryption methods
    such as Type 5 (MD5), Type 8 (PBKDF2), or Type 9 (scrypt) password hashing.
    """
    # Load device configurations from the test input
    test_input_file = os.environ.get('TEST_INPUT_JSON', 'test_input.json')
    with open(test_input_file, 'r') as f:
        test_input = json.load(f)
    
    # Patterns to detect cleartext passwords
    cleartext_patterns = [
        # Line passwords without encryption
        r'^\s*password\s+(?!hash|0|7|4|5|8|9)(\S+)',
        
        # Enable passwords without encryption
        r'^\s*enable\s+password\s+(?!hash|0|7|4|5|8|9)(\S+)',
        
        # Username with cleartext password
        r'^\s*username\s+\S+\s+password\s+(?!hash|0|7|4|5|8|9)(\S+)',
        
        # SNMP community strings
        r'^\s*snmp-server\s+community\s+(\S+)',
        
        # OSPF authentication without encryption
        r'^\s*ip\s+ospf\s+authentication-key\s+(\S+)',
        
        # EIGRP authentication without encryption
        r'^\s*ip\s+authentication\s+key-chain\s+eigrp',
        
        # BGP authentication without encryption
        r'^\s*neighbor\s+\S+\s+password\s+(?!hash|0|7|4|5|8|9)(\S+)',
        
        # HTTP authentication without encryption
        r'^\s*ip\s+http\s+authentication\s+local',
        
        # TACACS/RADIUS with cleartext shared secret
        r'^\s*tacacs-server\s+key\s+(?!hash|0|7|4|5|8|9)(\S+)',
        r'^\s*radius-server\s+key\s+(?!hash|0|7|4|5|8|9)(\S+)',
        
        # VPN pre-shared keys in cleartext
        r'^\s*crypto\s+isakmp\s+key\s+(?!hash|0|7|4|5|8|9)(\S+)',
    ]
    
    # Process each device in the test input
    for device in test_input.get('devices', []):
        device_name = device.get('name', 'Unknown Device')
        running_config = device.get('running_config', '')
        
        # Validate no cleartext passwords in the configuration
        cleartext_findings = []
        
        # Check each line of the configuration against the patterns
        for line_num, line in enumerate(running_config.splitlines(), 1):
            for pattern in cleartext_patterns:
                match = re.search(pattern, line)
                if match:
                    cleartext_findings.append({
                        'line_num': line_num,
                        'line': line.strip(),
                        'pattern': pattern
                    })
        
        # Check for service password-encryption
        has_password_encryption = any('service password-encryption' in line for line in running_config.splitlines())
        
        # Special case for devices without service password-encryption
        if not has_password_encryption:
            cleartext_findings.append({
                'line_num': 0,
                'line': 'Missing "service password-encryption" command',
                'pattern': 'service password-encryption'
            })
        
        # Assert no cleartext passwords found
        assert_message = f"Device {device_name} has cleartext passwords or missing encryption:\n"
        for finding in cleartext_findings:
            assert_message += f"  Line {finding['line_num']}: {finding['line']}\n"
        
        assert len(cleartext_findings) == 0, assert_message