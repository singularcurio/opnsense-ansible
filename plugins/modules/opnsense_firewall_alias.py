#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_firewall_alias
short_description: Manage OPNsense firewall aliases
version_added: "0.1.0"
description:
  - Create, update, and delete firewall aliases on an OPNsense firewall via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: compares desired fields against the current state and only mutates when something differs.
options:
  state:
    description: Desired state of the alias.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing alias.
      - When omitted, the module searches by I(name) to locate an existing alias.
    type: str
    required: false
  name:
    description:
      - Alias name (required for I(state=present) when I(uuid) is not given).
      - Used as the search key to find existing aliases when I(uuid) is omitted.
    type: str
    required: false
  enabled:
    description: Whether the alias is active.
    type: bool
    default: true
  type:
    description: Alias type (e.g. host, network, port, url, urltable, geoip, etc.).
    type: str
    required: false
  proto:
    description: Protocol filter (IPv4, IPv6, or empty for both).
    type: str
    required: false
  interface:
    description: Interface to associate with the alias (for interface type).
    type: str
    required: false
  counters:
    description: Enable packet counters for this alias.
    type: str
    required: false
  updatefreq:
    description: Update frequency in days for URL-based aliases.
    type: str
    required: false
  content:
    description: Alias content (hosts, networks, ports, URLs, etc.), newline separated.
    type: str
    required: false
  categories:
    description: Comma-separated list of category UUIDs.
    type: str
    required: false
  description:
    description: Human-readable description for this alias.
    type: str
    required: false
  reconfigure:
    description: Apply pending firewall alias changes immediately after mutating.
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
- name: Create a host alias
  opnsense.core.opnsense_firewall_alias:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    name: my_servers
    type: host
    content: "192.168.1.10\n192.168.1.11"
    description: My servers
    state: present
    reconfigure: true

- name: Remove a firewall alias
  opnsense.core.opnsense_firewall_alias:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    name: my_servers
    state: absent
    reconfigure: true
"""

RETURN = r"""
firewall_alias:
  description: The firewall alias object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    name: my_servers
    type: host
    enabled: "1"
    content: "192.168.1.10\n192.168.1.11"
    description: My servers
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
from opnsense_py.models.firewall import FirewallAlias

_FIELDS = (
    "name", "type", "proto", "interface", "counters", "updatefreq",
    "content", "categories", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple:
    try:
        alias = client.firewall.get_alias(uuid)
        return uuid, alias.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_name(client: OPNsenseClient, name: str) -> tuple:
    result = client.firewall.search_aliases(SearchRequest(searchPhrase=name))
    for alias in result.rows:
        row = alias.model_dump()
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
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("enabled") != _bool_to_api(desired_enabled):
            return True
    return False


def _build_obj(params: dict) -> FirewallAlias:
    enabled = params.get("enabled")
    return FirewallAlias(
        name=params.get("name"),
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        type=params.get("type"),
        proto=params.get("proto"),
        interface=params.get("interface"),
        counters=params.get("counters"),
        updatefreq=params.get("updatefreq"),
        content=params.get("content"),
        categories=params.get("categories"),
        description=params.get("description"),
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
            client.firewall.del_alias(existing_uuid)
            if params.get("reconfigure"):
                client.firewall.reconfigure_aliases()
        return {"changed": True}

    if not name:
        raise OPNsenseError("'name' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "firewall_alias": None}
        alias_obj = _build_obj(params)
        response = client.firewall.add_alias(alias_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.firewall.reconfigure_aliases()
        result = client.firewall.get_alias(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "firewall_alias": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "firewall_alias": existing}

    if check_mode:
        return {"changed": True, "firewall_alias": existing}

    alias_obj = _build_obj(params)
    client.firewall.set_alias(existing_uuid, alias_obj)
    if params.get("reconfigure"):
        client.firewall.reconfigure_aliases()
    result = client.firewall.get_alias(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "firewall_alias": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        name=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        type=dict(type="str", required=False, default=None),
        proto=dict(type="str", required=False, default=None),
        interface=dict(type="str", required=False, default=None),
        counters=dict(type="str", required=False, default=None),
        updatefreq=dict(type="str", required=False, default=None),
        content=dict(type="str", required=False, default=None),
        categories=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
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
