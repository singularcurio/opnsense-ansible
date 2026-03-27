#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_kea_v4_peer
short_description: Manage Kea DHCPv4 high-availability peers
version_added: "0.1.0"
description:
  - Create, update, and delete Kea DHCP high-availability peers on an OPNsense firewall.
  - Natural key is the I(name) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the Kea HA peer.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing Kea HA peer.
    type: str
    required: false
  name:
    description: Peer name. Used as natural key.
    type: str
    required: false
  role:
    description: Peer role (primary, secondary, standby).
    type: str
    required: false
  url:
    description: URL of the peer's control agent.
    type: str
    required: false
  reconfigure:
    description: Apply Kea DHCP changes immediately after mutating the peer.
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
- name: Create a Kea HA peer
  opnsense.core.opnsense_kea_v4_peer:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    name: primary
    role: primary
    url: "http://10.0.0.1:8000/"
    state: present
    reconfigure: true

- name: Remove a Kea HA peer
  opnsense.core.opnsense_kea_v4_peer:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    name: primary
    state: absent
    reconfigure: true
"""

RETURN = r"""
kea_v4_peer:
  description: The Kea HA peer object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    name: primary
    role: primary
    url: "http://10.0.0.1:8000/"
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
from opnsense_py.models.kea import KeaHaPeer

_FIELDS = ("name", "role", "url")


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.kea.get_v4_peer(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_name(client: OPNsenseClient, name: str):
    result = client.kea.search_v4_peers(SearchRequest(searchPhrase=name))
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


def _build_obj(params: dict) -> KeaHaPeer:
    return KeaHaPeer(
        name=params.get("name"),
        role=params.get("role"),
        url=params.get("url"),
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
            client.kea.del_v4_peer(existing_uuid)
            if params.get("reconfigure"):
                client.kea.reconfigure()
        return {"changed": True}

    if not name:
        raise OPNsenseError("'name' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "kea_v4_peer": None}
        obj = _build_obj(params)
        response = client.kea.add_v4_peer(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.kea.reconfigure()
        result = client.kea.get_v4_peer(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "kea_v4_peer": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "kea_v4_peer": existing}

    if check_mode:
        return {"changed": True, "kea_v4_peer": existing}

    obj = _build_obj(params)
    client.kea.set_v4_peer(existing_uuid, obj)
    if params.get("reconfigure"):
        client.kea.reconfigure()
    result = client.kea.get_v4_peer(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "kea_v4_peer": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        name=dict(type="str", required=False, default=None),
        role=dict(type="str", required=False, default=None),
        url=dict(type="str", required=False, default=None),
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
