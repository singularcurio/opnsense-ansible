#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_ipsec_pool
short_description: Manage IPsec address pools
version_added: "0.1.0"
description:
  - Create, update, and delete IPsec address pools on an OPNsense firewall.
  - Natural key is the I(name) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the IPsec pool.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing IPsec pool.
    type: str
    required: false
  name:
    description: Pool name. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the pool is active.
    type: bool
    default: true
  addrs:
    description: Address range or CIDR block for the pool.
    type: str
    required: false
  dns:
    description: DNS server(s) to assign to clients.
    type: str
    required: false
  reconfigure:
    description: Apply IPsec changes immediately after mutating the pool.
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
- name: Create an IPsec address pool
  opnsense.core.opnsense_ipsec_pool:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    name: vpn-pool
    addrs: "10.10.10.0/24"
    dns: "8.8.8.8"
    state: present
    reconfigure: true

- name: Remove an IPsec pool
  opnsense.core.opnsense_ipsec_pool:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    name: vpn-pool
    state: absent
    reconfigure: true
"""

RETURN = r"""
ipsec_pool:
  description: The IPsec pool object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    name: vpn-pool
    addrs: "10.10.10.0/24"
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
from opnsense_py.models.ipsec import IPsecPool

_FIELDS = ("name", "addrs", "dns")


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.ipsec.get_pool(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_name(client: OPNsenseClient, name: str):
    result = client.ipsec.search_pools(SearchRequest(searchPhrase=name))
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
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("enabled") != _bool_to_api(desired_enabled):
            return True
    return False


def _build_obj(params: dict) -> IPsecPool:
    enabled = params.get("enabled")
    return IPsecPool(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        name=params.get("name"),
        addrs=params.get("addrs"),
        dns=params.get("dns"),
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
            client.ipsec.del_pool(existing_uuid)
            if params.get("reconfigure"):
                client.ipsec.reconfigure()
        return {"changed": True}

    if not name:
        raise OPNsenseError("'name' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "ipsec_pool": None}
        obj = _build_obj(params)
        response = client.ipsec.add_pool(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.ipsec.reconfigure()
        result = client.ipsec.get_pool(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "ipsec_pool": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "ipsec_pool": existing}

    if check_mode:
        return {"changed": True, "ipsec_pool": existing}

    obj = _build_obj(params)
    client.ipsec.set_pool(existing_uuid, obj)
    if params.get("reconfigure"):
        client.ipsec.reconfigure()
    result = client.ipsec.get_pool(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "ipsec_pool": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        name=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        addrs=dict(type="str", required=False, default=None),
        dns=dict(type="str", required=False, default=None),
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
