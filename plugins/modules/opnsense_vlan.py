#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_vlan
short_description: Manage OPNsense VLAN interfaces
version_added: "0.1.0"
description:
  - Create, update, and delete VLAN interfaces on an OPNsense firewall.
  - Natural key is the composite of I(parent_interface) and I(tag).
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the VLAN.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing VLAN.
    type: str
    required: false
  parent_interface:
    description: Parent interface name (e.g. em0). Maps to the C(if) field in the API.
    type: str
    required: false
  tag:
    description: VLAN tag (802.1Q ID, 1-4094). Used as part of the composite natural key.
    type: int
    required: false
  pcp:
    description: Priority Code Point (802.1p).
    type: str
    required: false
  proto:
    description: VLAN protocol (802.1q or 802.1ad).
    type: str
    required: false
  descr:
    description: Human-readable description.
    type: str
    required: false
  reconfigure:
    description: Apply pending VLAN changes immediately.
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
- name: Create a VLAN
  opnsense.core.opnsense_vlan:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    parent_interface: em0
    tag: 10
    descr: "Management VLAN"
    state: present
    reconfigure: true

- name: Remove a VLAN
  opnsense.core.opnsense_vlan:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    parent_interface: em0
    tag: 10
    state: absent
"""

RETURN = r"""
vlan:
  description: The VLAN object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    if_: "em0"
    tag: 10
    descr: "Management VLAN"
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
from opnsense_py.models.interfaces import Vlan

_FIELDS = ("pcp", "proto", "descr")


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.interfaces.get_vlan(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_parent_tag(client: OPNsenseClient, parent_interface: str, tag: int):
    result = client.interfaces.search_vlans(SearchRequest(searchPhrase=str(tag)))
    for item in result.rows:
        row = item.model_dump()
        row_if = row.get("if") or row.get("if_")
        row_tag = row.get("tag")
        if row_if == parent_interface and row_tag == tag:
            uuid = row.get("uuid")
            if uuid:
                return uuid, {k: v for k, v in row.items() if v is not None}
    return None, None


def _needs_update(existing: dict, params: dict, parent_interface: str, tag: int) -> bool:
    # Check parent interface
    existing_if = existing.get("if") or existing.get("if_")
    if existing_if != parent_interface:
        return True
    # Check tag
    if existing.get("tag") != tag:
        return True
    # Check other fields
    for field in _FIELDS:
        desired = params.get(field)
        if desired is None:
            continue
        if existing.get(field) != desired:
            return True
    return False


def _build_obj(params: dict, parent_interface: str) -> Vlan:
    return Vlan(
        if_=parent_interface,
        tag=params.get("tag"),
        pcp=params.get("pcp"),
        proto=params.get("proto"),
        descr=params.get("descr"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    parent_interface = params.get("parent_interface")
    tag = params.get("tag")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif parent_interface and tag is not None:
        existing_uuid, existing = _find_by_parent_tag(client, parent_interface, tag)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.interfaces.del_vlan(existing_uuid)
            if params.get("reconfigure"):
                client.interfaces.reconfigure_vlans()
        return {"changed": True}

    if not parent_interface or tag is None:
        raise OPNsenseError("'parent_interface' and 'tag' are required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "vlan": None}
        vlan = _build_obj(params, parent_interface)
        response = client.interfaces.add_vlan(vlan)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.interfaces.reconfigure_vlans()
        result = client.interfaces.get_vlan(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "vlan": result}

    if not _needs_update(existing, params, parent_interface, tag):
        existing["uuid"] = existing_uuid
        return {"changed": False, "vlan": existing}

    if check_mode:
        return {"changed": True, "vlan": existing}

    vlan = _build_obj(params, parent_interface)
    client.interfaces.set_vlan(existing_uuid, vlan)
    if params.get("reconfigure"):
        client.interfaces.reconfigure_vlans()
    result = client.interfaces.get_vlan(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "vlan": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        parent_interface=dict(type="str", required=False, default=None),
        tag=dict(type="int", required=False, default=None),
        pcp=dict(type="str", required=False, default=None),
        proto=dict(type="str", required=False, default=None),
        descr=dict(type="str", required=False, default=None),
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
