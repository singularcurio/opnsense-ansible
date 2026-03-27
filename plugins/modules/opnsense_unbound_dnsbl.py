#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_unbound_dnsbl
short_description: Manage Unbound DNS blocklist entries
version_added: "0.1.0"
description:
  - Create, update, and delete Unbound DNS blocklist entries on an OPNsense firewall via the REST API.
  - Natural key is the I(description) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the Unbound DNSBL entry.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing Unbound DNSBL entry.
    type: str
    required: false
  description:
    description: DNSBL entry description. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the DNSBL entry is active.
    type: bool
    default: true
  type:
    description: Blocklist type (blacklist, whitelist).
    type: str
    required: false
  lists:
    description: Blocklist URLs or identifiers.
    type: str
    required: false
  allowlists:
    description: Allowlist URLs or identifiers.
    type: str
    required: false
  blocklists:
    description: Additional blocklist URLs.
    type: str
    required: false
  wildcards:
    description: Wildcard domains to block.
    type: str
    required: false
  source_nets:
    description: Source networks to apply blocklist to.
    type: str
    required: false
  address:
    description: IP address to return for blocked queries.
    type: str
    required: false
  nxdomain:
    description: Return NXDOMAIN instead of the redirect IP.
    type: str
    required: false
  cache_ttl:
    description: TTL for cached blocked responses.
    type: int
    required: false
  reconfigure:
    description: Apply Unbound changes immediately after mutating the DNSBL entry.
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
- name: Create a DNS blocklist entry
  opnsense.core.opnsense_unbound_dnsbl:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: Ad blocking list
    type: blacklist
    address: "0.0.0.0"
    state: present
    reconfigure: true

- name: Remove a DNSBL entry
  opnsense.core.opnsense_unbound_dnsbl:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: Ad blocking list
    state: absent
    reconfigure: true
"""

RETURN = r"""
unbound_dnsbl:
  description: The Unbound DNSBL entry object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    description: Ad blocking list
    enabled: "1"
    type: blacklist
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
from opnsense_py.models.unbound import UnboundDnsbl

_FIELDS = (
    "type", "lists", "allowlists", "blocklists", "wildcards", "source_nets",
    "address", "nxdomain", "cache_ttl", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.unbound.get_dnsbl(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(client: OPNsenseClient, description: str):
    result = client.unbound.search_dnsbl(SearchRequest(searchPhrase=description))
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


def _build_obj(params: dict) -> UnboundDnsbl:
    enabled = params.get("enabled")
    return UnboundDnsbl(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        type=params.get("type"),
        lists=params.get("lists"),
        allowlists=params.get("allowlists"),
        blocklists=params.get("blocklists"),
        wildcards=params.get("wildcards"),
        source_nets=params.get("source_nets"),
        address=params.get("address"),
        nxdomain=params.get("nxdomain"),
        cache_ttl=params.get("cache_ttl"),
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
            client.unbound.del_dnsbl(existing_uuid)
            if params.get("reconfigure"):
                client.unbound.reconfigure()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "unbound_dnsbl": None}
        obj = _build_obj(params)
        response = client.unbound.add_dnsbl(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.unbound.reconfigure()
        result = client.unbound.get_dnsbl(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "unbound_dnsbl": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "unbound_dnsbl": existing}

    if check_mode:
        return {"changed": True, "unbound_dnsbl": existing}

    obj = _build_obj(params)
    client.unbound.set_dnsbl(existing_uuid, obj)
    if params.get("reconfigure"):
        client.unbound.reconfigure()
    result = client.unbound.get_dnsbl(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "unbound_dnsbl": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        type=dict(type="str", required=False, default=None),
        lists=dict(type="str", required=False, default=None),
        allowlists=dict(type="str", required=False, default=None),
        blocklists=dict(type="str", required=False, default=None),
        wildcards=dict(type="str", required=False, default=None),
        source_nets=dict(type="str", required=False, default=None),
        address=dict(type="str", required=False, default=None),
        nxdomain=dict(type="str", required=False, default=None),
        cache_ttl=dict(type="int", required=False, default=None),
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
