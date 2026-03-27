#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_kea_v4_subnet
short_description: Manage Kea DHCPv4 subnets
version_added: "0.1.0"
description:
  - Create, update, and delete Kea DHCPv4 subnets on an OPNsense firewall.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the subnet.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing subnet. When provided, used for direct lookup.
    type: str
    required: false
  subnet:
    description: Subnet in CIDR notation (e.g. 192.168.1.0/24). Used as natural key.
    type: str
    required: false
  next_server:
    description: Next server address (TFTP/PXE boot).
    type: str
    required: false
  option_data_autocollect:
    description: Autocollect option data.
    type: str
    required: false
  pools:
    description: Address pools for this subnet.
    type: str
    required: false
  match_client_id:
    description: Whether to match by client-id.
    type: str
    required: false
  ddns_forward_zone:
    description: DDNS forward zone name.
    type: str
    required: false
  ddns_dns_server:
    description: DDNS DNS server address.
    type: str
    required: false
  description:
    description: Human-readable description.
    type: str
    required: false
  reconfigure:
    description: Apply pending Kea changes immediately.
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
- name: Create a Kea DHCPv4 subnet
  opnsense.core.opnsense_kea_v4_subnet:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    subnet: "192.168.1.0/24"
    pools: "192.168.1.100-192.168.1.200"
    description: "LAN subnet"
    state: present
    reconfigure: true

- name: Remove a Kea DHCPv4 subnet
  opnsense.core.opnsense_kea_v4_subnet:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    subnet: "192.168.1.0/24"
    state: absent
"""

RETURN = r"""
kea_v4_subnet:
  description: The Kea DHCPv4 subnet object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    subnet: "192.168.1.0/24"
    description: "LAN subnet"
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
from opnsense_py.models.kea import KeaSubnet4

_FIELDS = (
    "subnet", "next_server", "option_data_autocollect", "pools",
    "match_client_id", "ddns_forward_zone", "ddns_dns_server", "description",
)


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.kea.get_v4_subnet(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_subnet(client: OPNsenseClient, subnet: str):
    result = client.kea.search_v4_subnets(SearchRequest(searchPhrase=subnet))
    for item in result.rows:
        row = item.model_dump()
        if row.get("subnet") == subnet:
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


def _build_obj(params: dict) -> KeaSubnet4:
    return KeaSubnet4(
        subnet=params.get("subnet"),
        next_server=params.get("next_server"),
        option_data_autocollect=params.get("option_data_autocollect"),
        pools=params.get("pools"),
        match_client_id=params.get("match_client_id"),
        ddns_forward_zone=params.get("ddns_forward_zone"),
        ddns_dns_server=params.get("ddns_dns_server"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    subnet = params.get("subnet")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif subnet:
        existing_uuid, existing = _find_by_subnet(client, subnet)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.kea.del_v4_subnet(existing_uuid)
            if params.get("reconfigure"):
                client.kea.reconfigure()
        return {"changed": True}

    if not subnet:
        raise OPNsenseError("'subnet' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "kea_v4_subnet": None}
        obj = _build_obj(params)
        response = client.kea.add_v4_subnet(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.kea.reconfigure()
        result = client.kea.get_v4_subnet(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "kea_v4_subnet": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "kea_v4_subnet": existing}

    if check_mode:
        return {"changed": True, "kea_v4_subnet": existing}

    obj = _build_obj(params)
    client.kea.set_v4_subnet(existing_uuid, obj)
    if params.get("reconfigure"):
        client.kea.reconfigure()
    result = client.kea.get_v4_subnet(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "kea_v4_subnet": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        subnet=dict(type="str", required=False, default=None),
        next_server=dict(type="str", required=False, default=None),
        option_data_autocollect=dict(type="str", required=False, default=None),
        pools=dict(type="str", required=False, default=None),
        match_client_id=dict(type="str", required=False, default=None),
        ddns_forward_zone=dict(type="str", required=False, default=None),
        ddns_dns_server=dict(type="str", required=False, default=None),
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
