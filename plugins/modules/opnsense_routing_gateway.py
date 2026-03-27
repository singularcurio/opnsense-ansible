#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_routing_gateway
short_description: Manage OPNsense routing gateways
version_added: "0.1.0"
description:
  - Create, update, and delete routing gateways on an OPNsense firewall via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: compares desired fields against the current state and only mutates when something differs.
  - Natural key is the I(name) field.
options:
  state:
    description: Desired state of the gateway.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing gateway.
      - When omitted, the module searches by I(name).
    type: str
    required: false
  name:
    description:
      - Gateway name (required for I(state=present) when I(uuid) is not given).
      - Used as the search key.
    type: str
    required: false
  descr:
    description: Human-readable description.
    type: str
    required: false
  interface:
    description: Network interface this gateway is associated with.
    type: str
    required: false
  ipprotocol:
    description: IP protocol version (inet for IPv4, inet6 for IPv6).
    type: str
    required: false
  gateway:
    description: Gateway IP address.
    type: str
    required: false
  defaultgw:
    description: Set as the default gateway.
    type: str
    required: false
  fargw:
    description: Far gateway (gateway is not on a directly connected network).
    type: str
    required: false
  monitor_disable:
    description: Disable gateway monitoring.
    type: str
    required: false
  monitor_noroute:
    description: Do not create a host route for the monitor IP.
    type: str
    required: false
  monitor:
    description: Alternate monitor IP address.
    type: str
    required: false
  force_down:
    description: Force the gateway to be considered down.
    type: str
    required: false
  priority:
    description: Gateway priority (lower value = higher priority).
    type: int
    required: false
  weight:
    description: Gateway weight for load balancing.
    type: int
    required: false
  latencylow:
    description: Low latency threshold in milliseconds.
    type: int
    required: false
  latencyhigh:
    description: High latency threshold in milliseconds.
    type: int
    required: false
  losslow:
    description: Low packet loss threshold (percentage).
    type: int
    required: false
  losshigh:
    description: High packet loss threshold (percentage).
    type: int
    required: false
  interval:
    description: Probe interval in seconds.
    type: int
    required: false
  time_period:
    description: Time period in seconds over which results are averaged.
    type: int
    required: false
  loss_interval:
    description: Time in seconds before packets are considered lost.
    type: int
    required: false
  data_length:
    description: ICMP probe data length in bytes.
    type: int
    required: false
  enabled:
    description:
      - Whether the gateway is active. Maps to the API C(disabled) field (inverted).
    type: bool
    default: true
  reconfigure:
    description: Apply pending gateway changes immediately after mutating.
    type: bool
    default: false
  host:
    description: OPNsense hostname or IP. Falls back to C(OPNSENSE_HOST) env var.
    type: str
    required: false
  api_key:
    description: OPNsense API key. Falls back to C(OPNSENSE_API_KEY) env var.
    type: str
    required: false
    no_log: true
  api_secret:
    description: OPNsense API secret. Falls back to C(OPNSENSE_API_SECRET) env var.
    type: str
    required: false
    no_log: true
  verify_ssl:
    description: Verify TLS certificate. Set C(false) for self-signed certs.
    type: bool
    required: false
  port:
    description: Override the default port (443 for HTTPS, 80 for HTTP).
    type: int
    required: false
  https:
    description: Use HTTPS.
    type: bool
    default: true
author:
  - Justin Refi (@justinrefi)
"""

EXAMPLES = r"""
- name: Create a gateway
  opnsense.core.opnsense_routing_gateway:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    name: WAN_GW
    interface: wan
    ipprotocol: inet
    gateway: 203.0.113.1
    descr: WAN Gateway
    state: present
    reconfigure: true

- name: Remove a gateway
  opnsense.core.opnsense_routing_gateway:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    name: WAN_GW
    state: absent
    reconfigure: true
"""

RETURN = r"""
gateway:
  description: The gateway object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    name: WAN_GW
    interface: wan
    ipprotocol: inet
    gateway: 203.0.113.1
    disabled: "0"
    descr: WAN Gateway
"""

try:
    from ansible.module_utils.basic import AnsibleModule
    from ansible_collections.opnsense.core.plugins.module_utils.opnsense import (
        build_client,
        client_argument_spec,
    )
except ImportError:
    from ansible.module_utils.basic import AnsibleModule  # type: ignore[no-redef]
    from module_utils.opnsense import build_client, client_argument_spec  # type: ignore[no-redef]

from opnsense_py.client import OPNsenseClient
from opnsense_py.exceptions import OPNsenseError, OPNsenseNotFoundError
from opnsense_py.models.base import SearchRequest
from opnsense_py.models.routing import Gateway

_FIELDS = (
    "name", "descr", "interface", "ipprotocol", "gateway",
    "defaultgw", "fargw", "monitor_disable", "monitor_noroute", "monitor",
    "force_down", "priority", "weight", "latencylow", "latencyhigh",
    "losslow", "losshigh", "interval", "time_period", "loss_interval", "data_length",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple:
    try:
        gateway = client.routing.get_gateway(uuid)
        return uuid, gateway.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_name(client: OPNsenseClient, name: str) -> tuple:
    result = client.routing.search_gateways(SearchRequest(searchPhrase=name))
    for gateway in result.rows:
        row = gateway.model_dump()
        if row.get("name") == name:
            uuid = row.get("uuid")
            if uuid:
                return uuid, {k: v for k, v in row.items() if v is not None}
    return None, None


def _needs_update(existing: dict, params: dict) -> bool:
    for field in _FIELDS:
        desired = params.get(field)
        if desired is None:
            continue
        if existing.get(field) != desired:
            return True
    # enabled param maps to the inverted "disabled" API field
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        desired_disabled = "1" if not desired_enabled else "0"
        if existing.get("disabled") != desired_disabled:
            return True
    return False


def _build_obj(params: dict) -> Gateway:
    enabled = params.get("enabled")
    disabled = "1" if not enabled else "0"
    return Gateway(
        disabled=disabled,
        name=params.get("name"),
        descr=params.get("descr"),
        interface=params.get("interface"),
        ipprotocol=params.get("ipprotocol"),
        gateway=params.get("gateway"),
        defaultgw=params.get("defaultgw"),
        fargw=params.get("fargw"),
        monitor_disable=params.get("monitor_disable"),
        monitor_noroute=params.get("monitor_noroute"),
        monitor=params.get("monitor"),
        force_down=params.get("force_down"),
        priority=params.get("priority"),
        weight=params.get("weight"),
        latencylow=params.get("latencylow"),
        latencyhigh=params.get("latencyhigh"),
        losslow=params.get("losslow"),
        losshigh=params.get("losshigh"),
        interval=params.get("interval"),
        time_period=params.get("time_period"),
        loss_interval=params.get("loss_interval"),
        data_length=params.get("data_length"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    name = params.get("name")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif name:
        existing_uuid, existing = _find_by_name(client, name)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.routing.del_gateway(existing_uuid)
            if params.get("reconfigure"):
                client.routing.reconfigure()
        return {"changed": True}

    if not name:
        raise OPNsenseError("'name' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "gateway": None}
        gateway_obj = _build_obj(params)
        response = client.routing.add_gateway(gateway_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.routing.reconfigure()
        result = client.routing.get_gateway(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "gateway": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "gateway": existing}

    if check_mode:
        return {"changed": True, "gateway": existing}

    gateway_obj = _build_obj(params)
    client.routing.set_gateway(existing_uuid, gateway_obj)
    if params.get("reconfigure"):
        client.routing.reconfigure()
    result = client.routing.get_gateway(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "gateway": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        name=dict(type="str", required=False, default=None),
        descr=dict(type="str", required=False, default=None),
        interface=dict(type="str", required=False, default=None),
        ipprotocol=dict(type="str", required=False, default=None),
        gateway=dict(type="str", required=False, default=None),
        defaultgw=dict(type="str", required=False, default=None),
        fargw=dict(type="str", required=False, default=None),
        monitor_disable=dict(type="str", required=False, default=None),
        monitor_noroute=dict(type="str", required=False, default=None),
        monitor=dict(type="str", required=False, default=None),
        force_down=dict(type="str", required=False, default=None),
        priority=dict(type="int", required=False, default=None),
        weight=dict(type="int", required=False, default=None),
        latencylow=dict(type="int", required=False, default=None),
        latencyhigh=dict(type="int", required=False, default=None),
        losslow=dict(type="int", required=False, default=None),
        losshigh=dict(type="int", required=False, default=None),
        interval=dict(type="int", required=False, default=None),
        time_period=dict(type="int", required=False, default=None),
        loss_interval=dict(type="int", required=False, default=None),
        data_length=dict(type="int", required=False, default=None),
        enabled=dict(type="bool", default=True),
        reconfigure=dict(type="bool", default=False),
        **client_argument_spec(),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)
    client = build_client(module)
    try:
        result = run(module.params, module.check_mode, client)
    except OPNsenseError as exc:
        module.fail_json(msg=str(exc))
    finally:
        client.close()
    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == "__main__":
    main()
