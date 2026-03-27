#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_openvpn_instance
short_description: Manage OPNsense OpenVPN instances
version_added: "0.1.0"
description:
  - Create, update, and delete OpenVPN server/client instances on an OPNsense firewall.
  - Natural key is the I(description) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the OpenVPN instance.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing OpenVPN instance.
    type: str
    required: false
  description:
    description: Instance description. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the instance is active.
    type: bool
    default: true
  dev_type:
    description: Device type (tun, tap).
    type: str
    required: false
  proto:
    description: Protocol (udp, tcp).
    type: str
    required: false
  port:
    description: Port number.
    type: str
    required: false
  local:
    description: Local IP address to bind to.
    type: str
    required: false
  topology:
    description: Network topology (subnet, net30, p2p).
    type: str
    required: false
  remote:
    description: Remote server address (client mode).
    type: str
    required: false
  role:
    description: Instance role (server, client).
    type: str
    required: false
  server:
    description: IPv4 server network.
    type: str
    required: false
  server_ipv6:
    description: IPv6 server network.
    type: str
    required: false
  cert:
    description: Certificate UUID.
    type: str
    required: false
  ca:
    description: CA certificate UUID.
    type: str
    required: false
  crl:
    description: Certificate revocation list UUID.
    type: str
    required: false
  cert_depth:
    description: Certificate depth for verification.
    type: str
    required: false
  remote_cert_tls:
    description: Require remote certificate TLS extension.
    type: str
    required: false
  verify_client_cert:
    description: Client certificate verification mode.
    type: str
    required: false
  auth:
    description: HMAC digest algorithm.
    type: str
    required: false
  tls_key:
    description: TLS static key UUID.
    type: str
    required: false
  authmode:
    description: Authentication mode.
    type: str
    required: false
  local_group:
    description: Local group for authentication.
    type: str
    required: false
  maxclients:
    description: Maximum number of concurrent clients.
    type: int
    required: false
  keepalive_interval:
    description: Keepalive ping interval in seconds.
    type: int
    required: false
  keepalive_timeout:
    description: Keepalive timeout in seconds.
    type: int
    required: false
  reneg_sec:
    description: Renegotiation interval in seconds (0 = disabled).
    type: int
    required: false
  register_dns:
    description: Register DNS entries for clients.
    type: str
    required: false
  dns_domain:
    description: DNS domain to push to clients.
    type: str
    required: false
  dns_servers:
    description: DNS servers to push to clients.
    type: str
    required: false
  tun_mtu:
    description: TUN MTU size.
    type: int
    required: false
  carp_depend_on:
    description: CARP interface to depend on.
    type: str
    required: false
  reconfigure:
    description: Apply OpenVPN changes immediately after mutating the instance.
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
- name: Create an OpenVPN server instance
  opnsense.core.opnsense_openvpn_instance:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: Main VPN server
    role: server
    dev_type: tun
    proto: udp
    port: "1194"
    state: present
    reconfigure: true

- name: Remove an OpenVPN instance
  opnsense.core.opnsense_openvpn_instance:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: Main VPN server
    state: absent
    reconfigure: true
"""

RETURN = r"""
openvpn_instance:
  description: The OpenVPN instance object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    description: Main VPN server
    enabled: "1"
    role: server
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
from opnsense_py.models.openvpn import OpenVPNInstance

_FIELDS = (
    "dev_type", "proto", "port", "local", "topology", "remote", "role",
    "server", "server_ipv6", "cert", "ca", "crl", "cert_depth",
    "remote_cert_tls", "verify_client_cert", "auth", "tls_key", "authmode",
    "local_group", "maxclients", "keepalive_interval", "keepalive_timeout",
    "reneg_sec", "register_dns", "dns_domain", "dns_servers", "tun_mtu",
    "carp_depend_on", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.openvpn.get_instance(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(client: OPNsenseClient, description: str):
    result = client.openvpn.search_instances(SearchRequest(searchPhrase=description))
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


def _build_obj(params: dict) -> OpenVPNInstance:
    enabled = params.get("enabled")
    return OpenVPNInstance(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        dev_type=params.get("dev_type"),
        proto=params.get("proto"),
        port=params.get("port"),
        local=params.get("local"),
        topology=params.get("topology"),
        remote=params.get("remote"),
        role=params.get("role"),
        server=params.get("server"),
        server_ipv6=params.get("server_ipv6"),
        cert=params.get("cert"),
        ca=params.get("ca"),
        crl=params.get("crl"),
        cert_depth=params.get("cert_depth"),
        remote_cert_tls=params.get("remote_cert_tls"),
        verify_client_cert=params.get("verify_client_cert"),
        auth=params.get("auth"),
        tls_key=params.get("tls_key"),
        authmode=params.get("authmode"),
        local_group=params.get("local_group"),
        maxclients=params.get("maxclients"),
        keepalive_interval=params.get("keepalive_interval"),
        keepalive_timeout=params.get("keepalive_timeout"),
        reneg_sec=params.get("reneg_sec"),
        register_dns=params.get("register_dns"),
        dns_domain=params.get("dns_domain"),
        dns_servers=params.get("dns_servers"),
        tun_mtu=params.get("tun_mtu"),
        carp_depend_on=params.get("carp_depend_on"),
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
            client.openvpn.del_instance(existing_uuid)
            if params.get("reconfigure"):
                client.openvpn.reconfigure()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "openvpn_instance": None}
        obj = _build_obj(params)
        response = client.openvpn.add_instance(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.openvpn.reconfigure()
        result = client.openvpn.get_instance(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "openvpn_instance": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "openvpn_instance": existing}

    if check_mode:
        return {"changed": True, "openvpn_instance": existing}

    obj = _build_obj(params)
    client.openvpn.set_instance(existing_uuid, obj)
    if params.get("reconfigure"):
        client.openvpn.reconfigure()
    result = client.openvpn.get_instance(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "openvpn_instance": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        dev_type=dict(type="str", required=False, default=None),
        proto=dict(type="str", required=False, default=None),
        port=dict(type="str", required=False, default=None),
        local=dict(type="str", required=False, default=None),
        topology=dict(type="str", required=False, default=None),
        remote=dict(type="str", required=False, default=None),
        role=dict(type="str", required=False, default=None),
        server=dict(type="str", required=False, default=None),
        server_ipv6=dict(type="str", required=False, default=None),
        cert=dict(type="str", required=False, default=None),
        ca=dict(type="str", required=False, default=None),
        crl=dict(type="str", required=False, default=None),
        cert_depth=dict(type="str", required=False, default=None),
        remote_cert_tls=dict(type="str", required=False, default=None),
        verify_client_cert=dict(type="str", required=False, default=None),
        auth=dict(type="str", required=False, default=None),
        tls_key=dict(type="str", required=False, default=None),
        authmode=dict(type="str", required=False, default=None),
        local_group=dict(type="str", required=False, default=None),
        maxclients=dict(type="int", required=False, default=None),
        keepalive_interval=dict(type="int", required=False, default=None),
        keepalive_timeout=dict(type="int", required=False, default=None),
        reneg_sec=dict(type="int", required=False, default=None),
        register_dns=dict(type="str", required=False, default=None),
        dns_domain=dict(type="str", required=False, default=None),
        dns_servers=dict(type="str", required=False, default=None),
        tun_mtu=dict(type="int", required=False, default=None),
        carp_depend_on=dict(type="str", required=False, default=None),
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
