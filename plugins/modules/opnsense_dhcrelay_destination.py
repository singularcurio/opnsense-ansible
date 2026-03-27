#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_dhcrelay_destination
short_description: Manage DHCP relay destination servers
version_added: "0.1.0"
description:
  - Create, update, and delete DHCP relay destination servers on an OPNsense firewall.
  - Natural key is the I(name) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the relay destination.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing relay destination.
    type: str
    required: false
  name:
    description: Name of the relay destination. Used as natural key.
    type: str
    required: false
  server:
    description: Server address(es) for this destination.
    type: str
    required: false
  reconfigure:
    description: Apply pending DHCRelay changes immediately.
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
- name: Create a DHCP relay destination
  opnsense.core.opnsense_dhcrelay_destination:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    name: "primary-dhcp"
    server: "10.0.0.1"
    state: present
    reconfigure: true

- name: Remove a DHCP relay destination
  opnsense.core.opnsense_dhcrelay_destination:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    name: "primary-dhcp"
    state: absent
"""

RETURN = r"""
dhcrelay_destination:
  description: The DHCP relay destination object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    name: "primary-dhcp"
    server: "10.0.0.1"
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
from opnsense_py.models.dhcrelay import DHCRelayDestination

_FIELDS = ("name", "server")


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.dhcrelay.get_destination(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_name(client: OPNsenseClient, name: str):
    result = client.dhcrelay.search_destinations(SearchRequest(searchPhrase=name))
    for item in result.rows:
        row = item.model_dump()
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
    return False


def _build_obj(params: dict) -> DHCRelayDestination:
    return DHCRelayDestination(
        name=params.get("name"),
        server=params.get("server"),
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
            client.dhcrelay.del_destination(existing_uuid)
            if params.get("reconfigure"):
                client.dhcrelay.reconfigure()
        return {"changed": True}

    if not name:
        raise OPNsenseError("'name' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "dhcrelay_destination": None}
        obj = _build_obj(params)
        response = client.dhcrelay.add_destination(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.dhcrelay.reconfigure()
        result = client.dhcrelay.get_destination(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "dhcrelay_destination": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "dhcrelay_destination": existing}

    if check_mode:
        return {"changed": True, "dhcrelay_destination": existing}

    obj = _build_obj(params)
    client.dhcrelay.set_destination(existing_uuid, obj)
    if params.get("reconfigure"):
        client.dhcrelay.reconfigure()
    result = client.dhcrelay.get_destination(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "dhcrelay_destination": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        name=dict(type="str", required=False, default=None),
        server=dict(type="str", required=False, default=None),
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
