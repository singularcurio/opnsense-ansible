#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_unbound_forward
short_description: Manage OPNsense Unbound DNS forwards (DoT/forward zones)
version_added: "0.1.0"
description:
  - Create, update, and delete Unbound DNS forward/DNS-over-TLS entries on an OPNsense firewall.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: compares desired fields against the current state and only mutates when something differs.
  - Natural key is the I(server) field.
options:
  state:
    description: Desired state of the forward entry.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing forward entry.
      - When omitted, the module searches by I(server).
    type: str
    required: false
  enabled:
    description: Whether the forward is active.
    type: bool
    default: true
  type:
    description: Forward type (dot for DNS-over-TLS, forward for plain forwarding).
    type: str
    required: false
  domain:
    description: Domain to forward (leave empty for all domains).
    type: str
    required: false
  server:
    description:
      - Upstream DNS server address (required for I(state=present) when I(uuid) is not given).
      - Used as the search key.
    type: str
    required: false
  dns_port:
    description: Upstream DNS server port (maps to the C(port) API field).
    type: str
    required: false
  verify:
    description: TLS hostname to verify for DoT connections.
    type: str
    required: false
  forward_tcp_upstream:
    description: Use TCP for upstream connections.
    type: str
    required: false
  forward_first:
    description: Query this forwarder first before falling back to recursion.
    type: str
    required: false
  description:
    description: Human-readable description.
    type: str
    required: false
  reconfigure:
    description: Apply pending Unbound changes immediately after mutating.
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
  opnsense_port:
    description: Override the default OPNsense API port (443 for HTTPS, 80 for HTTP).
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
- name: Add a DNS-over-TLS forwarder
  opnsense.core.opnsense_unbound_forward:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    type: dot
    server: 1.1.1.1
    dns_port: "853"
    verify: cloudflare-dns.com
    description: Cloudflare DoT
    state: present
    reconfigure: true

- name: Remove a forward entry
  opnsense.core.opnsense_unbound_forward:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    server: 1.1.1.1
    state: absent
    reconfigure: true
"""

RETURN = r"""
forward:
  description: The forward entry object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    type: dot
    server: 1.1.1.1
    dns_port: "853"
    verify: cloudflare-dns.com
    enabled: "1"
    description: Cloudflare DoT
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
from opnsense_py.models.unbound import UnboundDot

_FIELDS = (
    "type", "domain", "server", "verify",
    "forward_tcp_upstream", "forward_first", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple:
    try:
        forward = client.unbound.get_forward(uuid)
        return uuid, forward.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_server(client: OPNsenseClient, server: str) -> tuple:
    result = client.unbound.search_forwards(SearchRequest(searchPhrase=server))
    for forward in result.rows:
        row = forward.model_dump()
        if row.get("server") == server:
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
    # dns_port maps to the API "port" field
    desired_dns_port = params.get("dns_port")
    if desired_dns_port is not None:
        if existing.get("port") != desired_dns_port:
            return True
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("enabled") != _bool_to_api(desired_enabled):
            return True
    return False


def _build_obj(params: dict) -> UnboundDot:
    enabled = params.get("enabled")
    return UnboundDot(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        type=params.get("type"),
        domain=params.get("domain"),
        server=params.get("server"),
        port=params.get("dns_port"),
        verify=params.get("verify"),
        forward_tcp_upstream=params.get("forward_tcp_upstream"),
        forward_first=params.get("forward_first"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    server = params.get("server")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif server:
        existing_uuid, existing = _find_by_server(client, server)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.unbound.del_forward(existing_uuid)
            if params.get("reconfigure"):
                client.unbound.reconfigure()
        return {"changed": True}

    if not server:
        raise OPNsenseError("'server' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "forward": None}
        forward_obj = _build_obj(params)
        response = client.unbound.add_forward(forward_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.unbound.reconfigure()
        result = client.unbound.get_forward(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "forward": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "forward": existing}

    if check_mode:
        return {"changed": True, "forward": existing}

    forward_obj = _build_obj(params)
    client.unbound.set_forward(existing_uuid, forward_obj)
    if params.get("reconfigure"):
        client.unbound.reconfigure()
    result = client.unbound.get_forward(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "forward": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        type=dict(type="str", required=False, default=None),
        domain=dict(type="str", required=False, default=None),
        server=dict(type="str", required=False, default=None),
        dns_port=dict(type="str", required=False, default=None),
        verify=dict(type="str", required=False, default=None),
        forward_tcp_upstream=dict(type="str", required=False, default=None),
        forward_first=dict(type="str", required=False, default=None),
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
