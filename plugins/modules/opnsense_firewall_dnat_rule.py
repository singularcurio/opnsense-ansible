#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_firewall_dnat_rule
short_description: Manage OPNsense destination NAT (port forward) rules
version_added: "0.1.0"
description:
  - Create, update, and delete destination NAT rules on an OPNsense firewall.
  - Natural key is the I(descr) field.
  - The DNatRule model uses a C(disabled) field; the Ansible param I(enabled) is
    converted as enabled=True -> disabled="0", enabled=False -> disabled="1".
  - Set I(reconfigure=true) to apply changes immediately (calls C(firewall.apply)).
options:
  state:
    description: Desired state of the DNAT rule.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing DNAT rule.
    type: str
    required: false
  descr:
    description: Rule description. Used as natural key when I(uuid) is not provided.
    type: str
    required: false
  enabled:
    description: Whether the rule is active. Stored as C(disabled) in the API.
    type: bool
    default: true
  sequence:
    description: Rule sequence/order.
    type: str
    required: false
  nordr:
    description: Disable redirection (no redirect).
    type: str
    required: false
  interface:
    description: Interface the rule applies to.
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
  target:
    description: Destination target address/host.
    type: str
    required: false
  local_port:
    description: Local port to redirect to.
    type: str
    required: false
  log:
    description: Log matched traffic.
    type: str
    required: false
  natreflection:
    description: NAT reflection setting.
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
- name: Create a DNAT port forward rule
  opnsense.core.opnsense_firewall_dnat_rule:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    descr: "Forward HTTP to webserver"
    interface: wan
    protocol: tcp
    target: "192.168.1.80"
    local_port: "80"
    state: present
    reconfigure: true

- name: Remove a DNAT rule
  opnsense.core.opnsense_firewall_dnat_rule:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    descr: "Forward HTTP to webserver"
    state: absent
"""

RETURN = r"""
dnat_rule:
  description: The DNAT rule object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    descr: "Forward HTTP to webserver"
    disabled: "0"
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
from opnsense_py.models.firewall import DNatRule

_FIELDS = (
    "sequence", "nordr", "interface", "ipprotocol", "protocol",
    "target", "local_port", "log", "natreflection", "descr",
)


def _enabled_to_disabled(enabled: bool) -> str:
    """Convert Ansible enabled bool to API disabled string."""
    return "0" if enabled else "1"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.firewall.get_dnat_rule(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_descr(client: OPNsenseClient, descr: str):
    result = client.firewall.search_dnat_rules(SearchRequest(searchPhrase=descr))
    for item in result.rows:
        row = item.model_dump()
        if row.get("descr") == descr:
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
    # enabled maps to disabled in the API
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("disabled") != _enabled_to_disabled(desired_enabled):
            return True
    return False


def _build_obj(params: dict) -> DNatRule:
    enabled = params.get("enabled")
    return DNatRule(
        disabled=_enabled_to_disabled(enabled) if enabled is not None else None,
        sequence=params.get("sequence"),
        nordr=params.get("nordr"),
        interface=params.get("interface"),
        ipprotocol=params.get("ipprotocol"),
        protocol=params.get("protocol"),
        target=params.get("target"),
        local_port=params.get("local_port"),
        log=params.get("log"),
        natreflection=params.get("natreflection"),
        descr=params.get("descr"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    descr = params.get("descr")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif descr:
        existing_uuid, existing = _find_by_descr(client, descr)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.firewall.del_dnat_rule(existing_uuid)
            if params.get("reconfigure"):
                client.firewall.apply()
        return {"changed": True}

    if not descr:
        raise OPNsenseError("'descr' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "dnat_rule": None}
        rule = _build_obj(params)
        response = client.firewall.add_dnat_rule(rule)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.firewall.apply()
        result = client.firewall.get_dnat_rule(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "dnat_rule": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "dnat_rule": existing}

    if check_mode:
        return {"changed": True, "dnat_rule": existing}

    rule = _build_obj(params)
    client.firewall.set_dnat_rule(existing_uuid, rule)
    if params.get("reconfigure"):
        client.firewall.apply()
    result = client.firewall.get_dnat_rule(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "dnat_rule": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        descr=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        sequence=dict(type="str", required=False, default=None),
        nordr=dict(type="str", required=False, default=None),
        interface=dict(type="str", required=False, default=None),
        ipprotocol=dict(type="str", required=False, default=None),
        protocol=dict(type="str", required=False, default=None),
        target=dict(type="str", required=False, default=None),
        local_port=dict(type="str", required=False, default=None),
        log=dict(type="str", required=False, default=None),
        natreflection=dict(type="str", required=False, default=None),
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
