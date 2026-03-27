#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_unbound_host_alias
short_description: Manage OPNsense Unbound DNS host aliases
version_added: "0.1.0"
description:
  - Create, update, and delete Unbound DNS host alias entries on an OPNsense firewall.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: compares desired fields against the current state and only mutates when something differs.
  - Natural key is the composite of I(hostname) and I(domain).
options:
  state:
    description: Desired state of the host alias.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing host alias.
      - When omitted, the module searches by I(hostname) and I(domain).
    type: str
    required: false
  enabled:
    description: Whether the host alias is active.
    type: bool
    default: true
  parent_host:
    description:
      - UUID of the parent host override this alias points to (maps to the C(host) field in the API).
    type: str
    required: false
  hostname:
    description:
      - Hostname part of the alias (required for I(state=present) when I(uuid) is not given).
      - Used as the search key together with I(domain).
    type: str
    required: false
  domain:
    description:
      - Domain part of the alias (required for I(state=present) when I(uuid) is not given).
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
- name: Create a DNS host alias
  opnsense.core.opnsense_unbound_host_alias:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    hostname: alias
    domain: example.com
    parent_host: "a1b2c3d4-0000-0000-0000-000000000001"
    description: Alias for myserver
    state: present
    reconfigure: true

- name: Remove a host alias
  opnsense.core.opnsense_unbound_host_alias:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    hostname: alias
    domain: example.com
    state: absent
    reconfigure: true
"""

RETURN = r"""
host_alias:
  description: The host alias object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000002"
    hostname: alias
    domain: example.com
    host: "a1b2c3d4-0000-0000-0000-000000000001"
    enabled: "1"
    description: Alias for myserver
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
from opnsense_py.models.unbound import HostAlias

_FIELDS = ("hostname", "domain", "description")


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple:
    try:
        alias = client.unbound.get_host_alias(uuid)
        return uuid, alias.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_hostname_domain(client: OPNsenseClient, hostname: str, domain: str) -> tuple:
    result = client.unbound.search_host_aliases(SearchRequest(searchPhrase=hostname))
    for alias in result.rows:
        row = alias.model_dump()
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
    # parent_host maps to the API "host" field
    desired_parent_host = params.get("parent_host")
    if desired_parent_host is not None:
        if existing.get("host") != desired_parent_host:
            return True
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("enabled") != _bool_to_api(desired_enabled):
            return True
    return False


def _build_obj(params: dict) -> HostAlias:
    enabled = params.get("enabled")
    return HostAlias(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        host=params.get("parent_host"),
        hostname=params.get("hostname"),
        domain=params.get("domain"),
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
            client.unbound.del_host_alias(existing_uuid)
            if params.get("reconfigure"):
                client.unbound.reconfigure()
        return {"changed": True}

    if not hostname or not domain:
        raise OPNsenseError("'hostname' and 'domain' are required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "host_alias": None}
        alias_obj = _build_obj(params)
        response = client.unbound.add_host_alias(alias_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.unbound.reconfigure()
        result = client.unbound.get_host_alias(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "host_alias": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "host_alias": existing}

    if check_mode:
        return {"changed": True, "host_alias": existing}

    alias_obj = _build_obj(params)
    client.unbound.set_host_alias(existing_uuid, alias_obj)
    if params.get("reconfigure"):
        client.unbound.reconfigure()
    result = client.unbound.get_host_alias(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "host_alias": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        parent_host=dict(type="str", required=False, default=None),
        hostname=dict(type="str", required=False, default=None),
        domain=dict(type="str", required=False, default=None),
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
