#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_ipsec_connection
short_description: Manage IPsec IKE connections
version_added: "0.1.0"
description:
  - Create, update, and delete IPsec IKE connections on an OPNsense firewall.
  - Natural key is the I(description) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the IPsec connection.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing IPsec connection.
    type: str
    required: false
  description:
    description: Connection description. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the connection is active.
    type: bool
    default: true
  proposals:
    description: IKE proposals.
    type: str
    required: false
  unique:
    description: Unique policy for IKE connections.
    type: str
    required: false
  aggressive:
    description: Use aggressive mode.
    type: str
    required: false
  version:
    description: IKE version (ikev1, ikev2).
    type: str
    required: false
  mobike:
    description: Enable MOBIKE.
    type: str
    required: false
  local_addrs:
    description: Local address(es).
    type: str
    required: false
  local_port:
    description: Local IKE port (string field, no conflict with connection port).
    type: str
    required: false
  remote_addrs:
    description: Remote address(es).
    type: str
    required: false
  remote_port:
    description: Remote IKE port (string field).
    type: str
    required: false
  encap:
    description: Force UDP encapsulation.
    type: str
    required: false
  reauth_time:
    description: IKE reauthentication time in seconds.
    type: int
    required: false
  rekey_time:
    description: IKE rekey time in seconds.
    type: int
    required: false
  over_time:
    description: IKE over time in seconds.
    type: int
    required: false
  dpd_delay:
    description: Dead peer detection delay in seconds.
    type: int
    required: false
  dpd_timeout:
    description: Dead peer detection timeout in seconds.
    type: int
    required: false
  pools:
    description: Address pools.
    type: str
    required: false
  send_certreq:
    description: Send certificate request.
    type: str
    required: false
  send_cert:
    description: Certificate sending policy.
    type: str
    required: false
  keyingtries:
    description: Number of keying tries.
    type: int
    required: false
  reconfigure:
    description: Apply pending IPsec changes immediately.
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
- name: Create an IPsec connection
  opnsense.core.opnsense_ipsec_connection:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: "Site-to-site VPN"
    remote_addrs: "203.0.113.1"
    version: ikev2
    state: present
    reconfigure: true

- name: Remove an IPsec connection
  opnsense.core.opnsense_ipsec_connection:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: "Site-to-site VPN"
    state: absent
"""

RETURN = r"""
ipsec_connection:
  description: The IPsec connection object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    description: "Site-to-site VPN"
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
from opnsense_py.models.ipsec import IPsecConnection

_FIELDS = (
    "proposals", "unique", "aggressive", "version", "mobike",
    "local_addrs", "local_port", "remote_addrs", "remote_port", "encap",
    "reauth_time", "rekey_time", "over_time", "dpd_delay", "dpd_timeout",
    "pools", "send_certreq", "send_cert", "keyingtries", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.ipsec.get_connection(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(client: OPNsenseClient, description: str):
    result = client.ipsec.search_connections(SearchRequest(searchPhrase=description))
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


def _build_obj(params: dict) -> IPsecConnection:
    enabled = params.get("enabled")
    return IPsecConnection(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        proposals=params.get("proposals"),
        unique=params.get("unique"),
        aggressive=params.get("aggressive"),
        version=params.get("version"),
        mobike=params.get("mobike"),
        local_addrs=params.get("local_addrs"),
        local_port=params.get("local_port"),
        remote_addrs=params.get("remote_addrs"),
        remote_port=params.get("remote_port"),
        encap=params.get("encap"),
        reauth_time=params.get("reauth_time"),
        rekey_time=params.get("rekey_time"),
        over_time=params.get("over_time"),
        dpd_delay=params.get("dpd_delay"),
        dpd_timeout=params.get("dpd_timeout"),
        pools=params.get("pools"),
        send_certreq=params.get("send_certreq"),
        send_cert=params.get("send_cert"),
        keyingtries=params.get("keyingtries"),
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
            client.ipsec.del_connection(existing_uuid)
            if params.get("reconfigure"):
                client.ipsec.reconfigure()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "ipsec_connection": None}
        conn = _build_obj(params)
        response = client.ipsec.add_connection(conn)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.ipsec.reconfigure()
        result = client.ipsec.get_connection(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "ipsec_connection": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "ipsec_connection": existing}

    if check_mode:
        return {"changed": True, "ipsec_connection": existing}

    conn = _build_obj(params)
    client.ipsec.set_connection(existing_uuid, conn)
    if params.get("reconfigure"):
        client.ipsec.reconfigure()
    result = client.ipsec.get_connection(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "ipsec_connection": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        proposals=dict(type="str", required=False, default=None),
        unique=dict(type="str", required=False, default=None),
        aggressive=dict(type="str", required=False, default=None),
        version=dict(type="str", required=False, default=None),
        mobike=dict(type="str", required=False, default=None),
        local_addrs=dict(type="str", required=False, default=None),
        local_port=dict(type="str", required=False, default=None),
        remote_addrs=dict(type="str", required=False, default=None),
        remote_port=dict(type="str", required=False, default=None),
        encap=dict(type="str", required=False, default=None),
        reauth_time=dict(type="int", required=False, default=None),
        rekey_time=dict(type="int", required=False, default=None),
        over_time=dict(type="int", required=False, default=None),
        dpd_delay=dict(type="int", required=False, default=None),
        dpd_timeout=dict(type="int", required=False, default=None),
        pools=dict(type="str", required=False, default=None),
        send_certreq=dict(type="str", required=False, default=None),
        send_cert=dict(type="str", required=False, default=None),
        keyingtries=dict(type="int", required=False, default=None),
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
