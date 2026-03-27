#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_radvd_entry
short_description: Manage Router Advertisement daemon entries
version_added: "0.1.0"
description:
  - Create, update, and delete radvd entries on an OPNsense firewall.
  - Natural key is the I(interface) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the radvd entry.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing radvd entry.
    type: str
    required: false
  interface:
    description: Interface name for router advertisements. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the radvd entry is active.
    type: bool
    default: true
  ra_flags:
    description: Router Advertisement flags.
    type: str
    required: false
  ra_prio:
    description: Router Advertisement priority.
    type: str
    required: false
  ra_interval:
    description: Router Advertisement interval.
    type: str
    required: false
  ra_lifetime:
    description: Router Advertisement lifetime.
    type: str
    required: false
  mtu:
    description: MTU to advertise.
    type: str
    required: false
  description:
    description: Human-readable description.
    type: str
    required: false
  reconfigure:
    description: Apply pending radvd changes immediately.
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
- name: Create a radvd entry
  opnsense.core.opnsense_radvd_entry:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    interface: "lan"
    enabled: true
    state: present
    reconfigure: true

- name: Remove a radvd entry
  opnsense.core.opnsense_radvd_entry:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    interface: "lan"
    state: absent
"""

RETURN = r"""
radvd_entry:
  description: The radvd entry object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    interface: "lan"
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
from opnsense_py.models.radvd import RadvdEntry

_FIELDS = ("interface", "ra_flags", "ra_prio", "ra_interval", "ra_lifetime", "mtu", "description")


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.radvd.get_entry(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_interface(client: OPNsenseClient, interface: str):
    result = client.radvd.search_entries(SearchRequest(searchPhrase=interface))
    for item in result.rows:
        row = item.model_dump()
        if row.get("interface") == interface:
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


def _build_obj(params: dict) -> RadvdEntry:
    enabled = params.get("enabled")
    return RadvdEntry(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        interface=params.get("interface"),
        ra_flags=params.get("ra_flags"),
        ra_prio=params.get("ra_prio"),
        ra_interval=params.get("ra_interval"),
        ra_lifetime=params.get("ra_lifetime"),
        mtu=params.get("mtu"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    interface = params.get("interface")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif interface:
        existing_uuid, existing = _find_by_interface(client, interface)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.radvd.del_entry(existing_uuid)
            if params.get("reconfigure"):
                client.radvd.reconfigure()
        return {"changed": True}

    if not interface:
        raise OPNsenseError("'interface' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "radvd_entry": None}
        obj = _build_obj(params)
        response = client.radvd.add_entry(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.radvd.reconfigure()
        result = client.radvd.get_entry(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "radvd_entry": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "radvd_entry": existing}

    if check_mode:
        return {"changed": True, "radvd_entry": existing}

    obj = _build_obj(params)
    client.radvd.set_entry(existing_uuid, obj)
    if params.get("reconfigure"):
        client.radvd.reconfigure()
    result = client.radvd.get_entry(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "radvd_entry": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        interface=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        ra_flags=dict(type="str", required=False, default=None),
        ra_prio=dict(type="str", required=False, default=None),
        ra_interval=dict(type="str", required=False, default=None),
        ra_lifetime=dict(type="str", required=False, default=None),
        mtu=dict(type="str", required=False, default=None),
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
