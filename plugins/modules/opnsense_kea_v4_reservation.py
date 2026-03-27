#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_kea_v4_reservation
short_description: Manage Kea DHCPv4 host reservations
version_added: "0.1.0"
description:
  - Create, update, and delete Kea DHCPv4 host reservations on an OPNsense firewall.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the reservation.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing reservation.
    type: str
    required: false
  ip_address:
    description: Reserved IP address. Used as natural key.
    type: str
    required: false
  subnet:
    description: UUID reference of the subnet this reservation belongs to.
    type: str
    required: false
  hw_address:
    description: Hardware (MAC) address for the reservation.
    type: str
    required: false
  hostname:
    description: Hostname to assign.
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
- name: Create a Kea DHCPv4 reservation
  opnsense.core.opnsense_kea_v4_reservation:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    ip_address: "192.168.1.50"
    hw_address: "aa:bb:cc:dd:ee:ff"
    hostname: "myserver"
    state: present
    reconfigure: true

- name: Remove a reservation
  opnsense.core.opnsense_kea_v4_reservation:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    ip_address: "192.168.1.50"
    state: absent
"""

RETURN = r"""
kea_v4_reservation:
  description: The Kea DHCPv4 reservation object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    ip_address: "192.168.1.50"
    hw_address: "aa:bb:cc:dd:ee:ff"
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
from opnsense_py.models.kea import KeaReservation4

_FIELDS = ("subnet", "ip_address", "hw_address", "hostname", "description")


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.kea.get_v4_reservation(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_ip_address(client: OPNsenseClient, ip_address: str):
    result = client.kea.search_v4_reservations(SearchRequest(searchPhrase=ip_address))
    for item in result.rows:
        row = item.model_dump()
        if row.get("ip_address") == ip_address:
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


def _build_obj(params: dict) -> KeaReservation4:
    return KeaReservation4(
        subnet=params.get("subnet"),
        ip_address=params.get("ip_address"),
        hw_address=params.get("hw_address"),
        hostname=params.get("hostname"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    ip_address = params.get("ip_address")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif ip_address:
        existing_uuid, existing = _find_by_ip_address(client, ip_address)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.kea.del_v4_reservation(existing_uuid)
            if params.get("reconfigure"):
                client.kea.reconfigure()
        return {"changed": True}

    if not ip_address:
        raise OPNsenseError("'ip_address' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "kea_v4_reservation": None}
        obj = _build_obj(params)
        response = client.kea.add_v4_reservation(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.kea.reconfigure()
        result = client.kea.get_v4_reservation(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "kea_v4_reservation": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "kea_v4_reservation": existing}

    if check_mode:
        return {"changed": True, "kea_v4_reservation": existing}

    obj = _build_obj(params)
    client.kea.set_v4_reservation(existing_uuid, obj)
    if params.get("reconfigure"):
        client.kea.reconfigure()
    result = client.kea.get_v4_reservation(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "kea_v4_reservation": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        ip_address=dict(type="str", required=False, default=None),
        subnet=dict(type="str", required=False, default=None),
        hw_address=dict(type="str", required=False, default=None),
        hostname=dict(type="str", required=False, default=None),
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
