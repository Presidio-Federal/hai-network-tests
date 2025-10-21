# purdue/level-3.5/tests/L3.5-SC7-001_test.py

"""
Test ID: L3.5-SC7-001
Control: SC-7(3) Boundary Protection
Intent: Ensure DMZ firewall denies IT->OT traffic except approved conduits.
"""

import pytest
from hai_tools import batfish_check, nso_cli_check

@pytest.mark.control("L3.5-SC7-001")
def test_boundary_protection_dmz():
    # Expected values come from purdue/level-3.5/expected-values.yml
    snapshot = "/opt/batfish/snapshots/dmz"
    result = batfish_check(snapshot, src_zone="IT", dst_zone="OT", port=502)
    assert not result.allowed, "IT→OT Modbus traffic was permitted — segmentation failure"

    acl_output = nso_cli_check("show access-lists dmz-fw | include 502")
    assert "deny" in acl_output, "Firewall ACL does not deny Modbus (502)"
