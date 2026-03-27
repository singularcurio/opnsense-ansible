#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_firewall_filter_rule
short_description: Manage OPNsense firewall filter rules
version_added: "0.1.0"
description:
  - Create, update, and delete firewall filter rules on an OPNsense firewall.
  - Natural key is I(description). Because descriptions may not be unique, providing
    I(uuid) directly is strongly preferred for update and delete operations.
  - Set I(reconfigure=true) to apply changes immediately (calls C(firewall.apply)).
options:
  state:
    description: Desired state of the filter rule.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing filter rule.
    type: str
    required: false
  description:
    description: Rule description. Used as natural key when I(uuid) is not provided.
    type: str
    required: false
  enabled:
    description: Whether the rule is active.
    type: bool
    default: true
  sequence:
    description: Rule sequence/order.
    type: str
    required: false
  action:
    description: Rule action (pass, block, reject).
    type: str
    required: false
  quick:
    description: Quick match (stop processing further rules on match).
    type: str
    required: false
  interface:
    description: Interface(s) the rule applies to.
    type: str
    required: false
  interfacenot:
    description: Invert interface match.
    type: str
    required: false
  direction:
    description: Traffic direction (in, out).
    type: str
    required: false
  ipprotocol:
    description: IP protocol version (inet, inet6).
    type: str
    required: false
  protocol:
    description: Network protocol (tcp, udp, etc.).
    type: str
    required: false
  source_net:
    description: Source network/address.
    type: str
    required: false
  source_not:
    description: Invert source match.
    type: str
    required: false
  source_port:
    description: Source port or port range.
    type: str
    required: false
  destination_net:
    description: Destination network/address.
    type: str
    required: false
  destination_not:
    description: Invert destination match.
    type: str
    required: false
  destination_port:
    description: Destination port or port range.
    type: str
    required: false
  gateway:
    description: Gateway to route matched traffic through.
    type: str
    required: false
  log:
    description: Log matched traffic.
    type: str
    required: false
  statetype:
    description: State type for stateful tracking.
    type: str
    required: false
  categories:
    description: Rule categories.
    type: str
    required: false
  reconfigure:
    description: Apply pending firewall changes immediately.
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
    description: Verify TLS certificate.
    type: bool
    required: false
  port:
    description: Override the default port.
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
- name: Allow HTTPS traffic on LAN
  opnsense.core.opnsense_firewall_filter_rule:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: "Allow HTTPS from LAN"
    action: pass
    interface: lan
    protocol: tcp
    destination_port: "443"
    state: present
    reconfigure: true

- name: Remove a filter rule by UUID
  opnsense.core.opnsense_firewall_filter_rule:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    state: absent
"""

RETURN = r"""
filter_rule:
  description: The filter rule object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    description: "Allow HTTPS from LAN"
    action: "pass"
    enabled: "1"
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
from opnsense_py.models.firewall import FilterRule

_FIELDS = (
    "sequence", "action", "quick", "interface", "interfacenot", "direction",
    "ipprotocol", "protocol", "source_net", "source_not", "source_port",
    "destination_net", "destination_not", "destination_port", "gateway",
    "log", "statetype", "categories", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.firewall.get_filter_rule(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(client: OPNsenseClient, description: str):
    result = client.firewall.search_filter_rules(SearchRequest(searchPhrase=description))
    for item in result.rows:
        row = item.model_dump()
        if row.get("description") == description:
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
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("enabled") != _bool_to_api(desired_enabled):
            return True
    return False


def _build_obj(params: dict) -> FilterRule:
    enabled = params.get("enabled")
    return FilterRule(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        sequence=params.get("sequence"),
        action=params.get("action"),
        quick=params.get("quick"),
        interface=params.get("interface"),
        interfacenot=params.get("interfacenot"),
        direction=params.get("direction"),
        ipprotocol=params.get("ipprotocol"),
        protocol=params.get("protocol"),
        source_net=params.get("source_net"),
        source_not=params.get("source_not"),
        source_port=params.get("source_port"),
        destination_net=params.get("destination_net"),
        destination_not=params.get("destination_not"),
        destination_port=params.get("destination_port"),
        gateway=params.get("gateway"),
        log=params.get("log"),
        statetype=params.get("statetype"),
        categories=params.get("categories"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    description = params.get("description")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif description:
        existing_uuid, existing = _find_by_description(client, description)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.firewall.del_filter_rule(existing_uuid)
            if params.get("reconfigure"):
                client.firewall.apply()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "filter_rule": None}
        rule = _build_obj(params)
        response = client.firewall.add_filter_rule(rule)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.firewall.apply()
        result = client.firewall.get_filter_rule(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "filter_rule": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "filter_rule": existing}

    if check_mode:
        return {"changed": True, "filter_rule": existing}

    rule = _build_obj(params)
    client.firewall.set_filter_rule(existing_uuid, rule)
    if params.get("reconfigure"):
        client.firewall.apply()
    result = client.firewall.get_filter_rule(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "filter_rule": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        sequence=dict(type="str", required=False, default=None),
        action=dict(type="str", required=False, default=None),
        quick=dict(type="str", required=False, default=None),
        interface=dict(type="str", required=False, default=None),
        interfacenot=dict(type="str", required=False, default=None),
        direction=dict(type="str", required=False, default=None),
        ipprotocol=dict(type="str", required=False, default=None),
        protocol=dict(type="str", required=False, default=None),
        source_net=dict(type="str", required=False, default=None),
        source_not=dict(type="str", required=False, default=None),
        source_port=dict(type="str", required=False, default=None),
        destination_net=dict(type="str", required=False, default=None),
        destination_not=dict(type="str", required=False, default=None),
        destination_port=dict(type="str", required=False, default=None),
        gateway=dict(type="str", required=False, default=None),
        log=dict(type="str", required=False, default=None),
        statetype=dict(type="str", required=False, default=None),
        categories=dict(type="str", required=False, default=None),
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
