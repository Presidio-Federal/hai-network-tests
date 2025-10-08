import pytest

REQUIREMENT_DR_1 = "EG-DR-1: Dynamic routing only allowed on Outer Encryption Component"

@pytest.mark.eg_dr_1
def test_dynamic_routing_only_on_outer_encryption_component(device_config):
    """Validates EG-DR-1: Dynamic routing only allowed on Outer Encryption Component."""
    config = device_config["mdd_data"]["config"]["junos:configuration"]
    device_name = config["system"]["host-name"]

    # Step 1: Check if dynamic routing is configured on this device
    protocols = config.get("protocols", {})
    dynamic_protocols = [proto for proto in ["ospf", "bgp", "rip", "isis"] if proto in protocols]
    has_dynamic_routing = bool(dynamic_protocols)

    # Step 2: If this is a Gray Firewall, dynamic routing must not be configured
    if device_name in ["HQ-GRAY-FW", "BRANCH-GRAY-FW"]:
        assert not has_dynamic_routing, (
            f"{REQUIREMENT_DR_1} — Dynamic routing protocols {', '.join(dynamic_protocols)} "
            f"not allowed on Gray Firewall {device_name}"
        )
    # Step 3: If this is an Outer Encryption Component, dynamic routing is allowed
    elif device_name in ["HQ-GRAY-ROUTER", "BRANCH-GRAY-ROUTER"]:
        # Dynamic routing is allowed, no assertion needed
        pass
    # Step 4: For all other devices, dynamic routing must not be configured
    else:
        assert not has_dynamic_routing, (
            f"{REQUIREMENT_DR_1} — Dynamic routing protocols {', '.join(dynamic_protocols)} "
            f"not allowed on non-Outer Encryption Component device {device_name}"
        )