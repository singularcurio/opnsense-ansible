#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_wireguard_server
short_description: Manage WireGuard server instances
version_added: "0.1.0"
description:
  - Create, update, and delete WireGuard server instances on an OPNsense firewall.
  - Natural key is the I(name) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the WireGuard server.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing WireGuard server.
    type: str
    required: false
  name:
    description: WireGuard server instance name. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the server instance is active.
    type: bool
    default: true
  pubkey:
    description: Server public key.
    type: str
    required: false
  privkey:
    description: Server private key.
    type: str
    required: false
    no_log: true
  server_port:
    description: UDP port to listen on. Maps to the C(port) field in the API.
    type: str
    required: false
  mtu:
    description: MTU for the WireGuard interface.
    type: int
    required: false
  dns:
    description: DNS server(s) to push to peers.
    type: str
    required: false
  tunneladdress:
    description: Tunnel address(es) for this server.
    type: str
    required: false
  disableroutes:
    description: Disable automatic route installation.
    type: str
    required: false
  gateway:
    description: Gateway address.
    type: str
    required: false
  peers:
    description: Comma-separated list of peer UUIDs.
    type: str
    required: false
  debug:
    description: Enable debug logging.
    type: str
    required: false
  reconfigure:
    description: Apply pending WireGuard changes immediately.
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
- name: Create a WireGuard server
  opnsense.core.opnsense_wireguard_server:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    name: "wg0"
    server_port: "51820"
    tunneladdress: "10.10.0.1/24"
    state: present
    reconfigure: true

- name: Remove a WireGuard server
  opnsense.core.opnsense_wireguard_server:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    name: "wg0"
    state: absent
"""

RETURN = r"""
wireguard_server:
  description: The WireGuard server object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    name: "wg0"
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
from opnsense_py.models.wireguard import WireguardServer

# server_port maps to port in the model; compare against existing["port"]
_FIELDS = (
    "name", "pubkey", "privkey", "mtu", "dns",
    "tunneladdress", "disableroutes", "gateway", "peers", "debug",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.wireguard.get_server(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_name(client: OPNsenseClient, name: str):
    result = client.wireguard.search_servers(SearchRequest(searchPhrase=name))
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
    # server_port maps to port in the stored object
    desired_port = params.get("server_port")
    if desired_port is not None:
        if existing.get("port") != desired_port:
            return True
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("enabled") != _bool_to_api(desired_enabled):
            return True
    return False


def _build_obj(params: dict) -> WireguardServer:
    enabled = params.get("enabled")
    return WireguardServer(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        name=params.get("name"),
        pubkey=params.get("pubkey"),
        privkey=params.get("privkey"),
        port=params.get("server_port"),
        mtu=params.get("mtu"),
        dns=params.get("dns"),
        tunneladdress=params.get("tunneladdress"),
        disableroutes=params.get("disableroutes"),
        gateway=params.get("gateway"),
        peers=params.get("peers"),
        debug=params.get("debug"),
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
            client.wireguard.del_server(existing_uuid)
            if params.get("reconfigure"):
                client.wireguard.reconfigure()
        return {"changed": True}

    if not name:
        raise OPNsenseError("'name' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "wireguard_server": None}
        server = _build_obj(params)
        response = client.wireguard.add_server(server)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.wireguard.reconfigure()
        result = client.wireguard.get_server(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "wireguard_server": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "wireguard_server": existing}

    if check_mode:
        return {"changed": True, "wireguard_server": existing}

    server = _build_obj(params)
    client.wireguard.set_server(existing_uuid, server)
    if params.get("reconfigure"):
        client.wireguard.reconfigure()
    result = client.wireguard.get_server(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "wireguard_server": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        name=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        pubkey=dict(type="str", required=False, default=None),
        privkey=dict(type="str", required=False, default=None, no_log=True),
        server_port=dict(type="str", required=False, default=None),
        mtu=dict(type="int", required=False, default=None),
        dns=dict(type="str", required=False, default=None),
        tunneladdress=dict(type="str", required=False, default=None),
        disableroutes=dict(type="str", required=False, default=None),
        gateway=dict(type="str", required=False, default=None),
        peers=dict(type="str", required=False, default=None),
        debug=dict(type="str", required=False, default=None),
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
