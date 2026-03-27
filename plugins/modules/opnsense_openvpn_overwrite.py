#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_openvpn_overwrite
short_description: Manage OPNsense OpenVPN client-specific overrides
version_added: "0.1.0"
description:
  - Create, update, and delete OpenVPN client-specific override entries on an OPNsense firewall.
  - Natural key is the I(common_name) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the OpenVPN overwrite.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing OpenVPN overwrite.
    type: str
    required: false
  common_name:
    description: Client certificate common name. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the override is active.
    type: bool
    default: true
  servers:
    description: OpenVPN server instance UUIDs this override applies to.
    type: str
    required: false
  block:
    description: Block this client from connecting.
    type: str
    required: false
  push_reset:
    description: Reset all client-pushed options.
    type: str
    required: false
  tunnel_network:
    description: IPv4 tunnel network for this client.
    type: str
    required: false
  tunnel_networkv6:
    description: IPv6 tunnel network for this client.
    type: str
    required: false
  local_networks:
    description: Local networks to push to this client.
    type: str
    required: false
  remote_networks:
    description: Remote networks for this client.
    type: str
    required: false
  route_gateway:
    description: Route gateway override.
    type: str
    required: false
  redirect_gateway:
    description: Redirect gateway flags.
    type: str
    required: false
  register_dns:
    description: Register DNS entries for this client.
    type: str
    required: false
  dns_domain:
    description: DNS domain to push to this client.
    type: str
    required: false
  dns_servers:
    description: DNS servers to push to this client.
    type: str
    required: false
  ntp_servers:
    description: NTP servers to push to this client.
    type: str
    required: false
  wins_servers:
    description: WINS servers to push to this client.
    type: str
    required: false
  description:
    description: Override description.
    type: str
    required: false
  reconfigure:
    description: Apply OpenVPN changes immediately after mutating the overwrite.
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
- name: Create an OpenVPN client override
  opnsense.core.opnsense_openvpn_overwrite:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    common_name: user@example.com
    tunnel_network: "10.8.0.5/24"
    state: present
    reconfigure: true

- name: Remove an OpenVPN client override
  opnsense.core.opnsense_openvpn_overwrite:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    common_name: user@example.com
    state: absent
    reconfigure: true
"""

RETURN = r"""
openvpn_overwrite:
  description: The OpenVPN client override object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    common_name: user@example.com
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
from opnsense_py.models.openvpn import OpenVPNOverwrite

_FIELDS = (
    "servers", "common_name", "block", "push_reset", "tunnel_network",
    "tunnel_networkv6", "local_networks", "remote_networks", "route_gateway",
    "redirect_gateway", "register_dns", "dns_domain", "dns_servers",
    "ntp_servers", "wins_servers", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.openvpn.get_client_overwrite(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_common_name(client: OPNsenseClient, common_name: str):
    result = client.openvpn.search_client_overwrites(SearchRequest(searchPhrase=common_name))
    for item in result.rows:
        row = item.model_dump()
        if row.get("common_name") == common_name:
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


def _build_obj(params: dict) -> OpenVPNOverwrite:
    enabled = params.get("enabled")
    return OpenVPNOverwrite(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        servers=params.get("servers"),
        common_name=params.get("common_name"),
        block=params.get("block"),
        push_reset=params.get("push_reset"),
        tunnel_network=params.get("tunnel_network"),
        tunnel_networkv6=params.get("tunnel_networkv6"),
        local_networks=params.get("local_networks"),
        remote_networks=params.get("remote_networks"),
        route_gateway=params.get("route_gateway"),
        redirect_gateway=params.get("redirect_gateway"),
        register_dns=params.get("register_dns"),
        dns_domain=params.get("dns_domain"),
        dns_servers=params.get("dns_servers"),
        ntp_servers=params.get("ntp_servers"),
        wins_servers=params.get("wins_servers"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    common_name = params.get("common_name")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif common_name:
        existing_uuid, existing = _find_by_common_name(client, common_name)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.openvpn.del_client_overwrite(existing_uuid)
            if params.get("reconfigure"):
                client.openvpn.reconfigure()
        return {"changed": True}

    if not common_name:
        raise OPNsenseError("'common_name' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "openvpn_overwrite": None}
        obj = _build_obj(params)
        response = client.openvpn.add_client_overwrite(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.openvpn.reconfigure()
        result = client.openvpn.get_client_overwrite(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "openvpn_overwrite": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "openvpn_overwrite": existing}

    if check_mode:
        return {"changed": True, "openvpn_overwrite": existing}

    obj = _build_obj(params)
    client.openvpn.set_client_overwrite(existing_uuid, obj)
    if params.get("reconfigure"):
        client.openvpn.reconfigure()
    result = client.openvpn.get_client_overwrite(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "openvpn_overwrite": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        common_name=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        servers=dict(type="str", required=False, default=None),
        block=dict(type="str", required=False, default=None),
        push_reset=dict(type="str", required=False, default=None),
        tunnel_network=dict(type="str", required=False, default=None),
        tunnel_networkv6=dict(type="str", required=False, default=None),
        local_networks=dict(type="str", required=False, default=None),
        remote_networks=dict(type="str", required=False, default=None),
        route_gateway=dict(type="str", required=False, default=None),
        redirect_gateway=dict(type="str", required=False, default=None),
        register_dns=dict(type="str", required=False, default=None),
        dns_domain=dict(type="str", required=False, default=None),
        dns_servers=dict(type="str", required=False, default=None),
        ntp_servers=dict(type="str", required=False, default=None),
        wins_servers=dict(type="str", required=False, default=None),
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
