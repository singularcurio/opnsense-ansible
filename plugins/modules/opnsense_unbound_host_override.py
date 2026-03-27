#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_unbound_host_override
short_description: Manage OPNsense Unbound DNS host overrides
version_added: "0.1.0"
description:
  - Create, update, and delete Unbound DNS host override entries on an OPNsense firewall.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: compares desired fields against the current state and only mutates when something differs.
  - Natural key is the composite of I(hostname) and I(domain).
options:
  state:
    description: Desired state of the host override.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing host override.
      - When omitted, the module searches by I(hostname) and I(domain).
    type: str
    required: false
  enabled:
    description: Whether the host override is active.
    type: bool
    default: true
  hostname:
    description:
      - Hostname part of the DNS record (required for I(state=present) when I(uuid) is not given).
      - Used as the search key together with I(domain).
    type: str
    required: false
  domain:
    description:
      - Domain part of the DNS record (required for I(state=present) when I(uuid) is not given).
    type: str
    required: false
  rr:
    description: Resource record type (A, AAAA, MX, etc.).
    type: str
    required: false
  mxprio:
    description: MX record priority.
    type: int
    required: false
  mx:
    description: MX mail exchange hostname.
    type: str
    required: false
  ttl:
    description: Time-to-live in seconds.
    type: int
    required: false
  server:
    description: IP address the hostname resolves to.
    type: str
    required: false
  txtdata:
    description: TXT record data.
    type: str
    required: false
  addptr:
    description: Also add a PTR record.
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
- name: Create a DNS host override
  opnsense.core.opnsense_unbound_host_override:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    hostname: myserver
    domain: example.com
    rr: A
    server: 192.168.1.100
    description: My server
    state: present
    reconfigure: true

- name: Remove a host override
  opnsense.core.opnsense_unbound_host_override:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    hostname: myserver
    domain: example.com
    state: absent
    reconfigure: true
"""

RETURN = r"""
host_override:
  description: The host override object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    hostname: myserver
    domain: example.com
    rr: A
    server: 192.168.1.100
    enabled: "1"
    description: My server
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
from opnsense_py.models.unbound import HostOverride

_FIELDS = (
    "hostname", "domain", "rr", "mxprio", "mx", "ttl",
    "server", "txtdata", "addptr", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple:
    try:
        host = client.unbound.get_host_override(uuid)
        return uuid, host.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_hostname_domain(client: OPNsenseClient, hostname: str, domain: str) -> tuple:
    result = client.unbound.search_host_overrides(SearchRequest(searchPhrase=hostname))
    for host in result.rows:
        row = host.model_dump()
        if row.get("hostname") == hostname and row.get("domain") == domain:
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


def _build_obj(params: dict) -> HostOverride:
    enabled = params.get("enabled")
    return HostOverride(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        hostname=params.get("hostname"),
        domain=params.get("domain"),
        rr=params.get("rr"),
        mxprio=params.get("mxprio"),
        mx=params.get("mx"),
        ttl=params.get("ttl"),
        server=params.get("server"),
        txtdata=params.get("txtdata"),
        addptr=params.get("addptr"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    hostname = params.get("hostname")
    domain = params.get("domain")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif hostname and domain:
        existing_uuid, existing = _find_by_hostname_domain(client, hostname, domain)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.unbound.del_host_override(existing_uuid)
            if params.get("reconfigure"):
                client.unbound.reconfigure()
        return {"changed": True}

    if not hostname or not domain:
        raise OPNsenseError("'hostname' and 'domain' are required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "host_override": None}
        host_obj = _build_obj(params)
        response = client.unbound.add_host_override(host_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.unbound.reconfigure()
        result = client.unbound.get_host_override(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "host_override": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "host_override": existing}

    if check_mode:
        return {"changed": True, "host_override": existing}

    host_obj = _build_obj(params)
    client.unbound.set_host_override(existing_uuid, host_obj)
    if params.get("reconfigure"):
        client.unbound.reconfigure()
    result = client.unbound.get_host_override(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "host_override": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        hostname=dict(type="str", required=False, default=None),
        domain=dict(type="str", required=False, default=None),
        rr=dict(type="str", required=False, default=None),
        mxprio=dict(type="int", required=False, default=None),
        mx=dict(type="str", required=False, default=None),
        ttl=dict(type="int", required=False, default=None),
        server=dict(type="str", required=False, default=None),
        txtdata=dict(type="str", required=False, default=None),
        addptr=dict(type="str", required=False, default=None),
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
