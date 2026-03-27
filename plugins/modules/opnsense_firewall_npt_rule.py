#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_firewall_npt_rule
short_description: Manage OPNsense firewall NPT (Network Prefix Translation) rules
version_added: "0.1.0"
description:
  - Create, update, and delete NPT rules on an OPNsense firewall via the REST API.
  - Natural key is the I(description) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the NPT rule.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing NPT rule.
    type: str
    required: false
  description:
    description: Rule description. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the rule is active.
    type: bool
    default: true
  log:
    description: Enable logging for this rule.
    type: str
    required: false
  sequence:
    description: Rule sequence number.
    type: str
    required: false
  interface:
    description: Network interface for the rule.
    type: str
    required: false
  source_net:
    description: Source IPv6 prefix.
    type: str
    required: false
  destination_net:
    description: Destination IPv6 prefix.
    type: str
    required: false
  trackif:
    description: Interface to track for prefix.
    type: str
    required: false
  categories:
    description: Rule categories.
    type: str
    required: false
  reconfigure:
    description: Apply firewall changes immediately after mutating the rule.
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
- name: Create an NPT rule
  opnsense.core.opnsense_firewall_npt_rule:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: IPv6 prefix translation
    interface: wan
    source_net: "fd00::/48"
    destination_net: "2001:db8::/48"
    state: present
    reconfigure: true

- name: Remove an NPT rule
  opnsense.core.opnsense_firewall_npt_rule:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: IPv6 prefix translation
    state: absent
    reconfigure: true
"""

RETURN = r"""
firewall_npt_rule:
  description: The NPT rule object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    description: IPv6 prefix translation
    enabled: "1"
    interface: wan
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
from opnsense_py.models.firewall import NPTRule

_FIELDS = (
    "log", "sequence", "interface", "source_net", "destination_net",
    "trackif", "categories", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.firewall.get_npt_rule(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(client: OPNsenseClient, description: str):
    result = client.firewall.search_npt_rules(SearchRequest(searchPhrase=description))
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


def _build_obj(params: dict) -> NPTRule:
    enabled = params.get("enabled")
    return NPTRule(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        log=params.get("log"),
        sequence=params.get("sequence"),
        interface=params.get("interface"),
        source_net=params.get("source_net"),
        destination_net=params.get("destination_net"),
        trackif=params.get("trackif"),
        categories=params.get("categories"),
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
            client.firewall.del_npt_rule(existing_uuid)
            if params.get("reconfigure"):
                client.firewall.apply()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "firewall_npt_rule": None}
        obj = _build_obj(params)
        response = client.firewall.add_npt_rule(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.firewall.apply()
        result = client.firewall.get_npt_rule(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "firewall_npt_rule": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "firewall_npt_rule": existing}

    if check_mode:
        return {"changed": True, "firewall_npt_rule": existing}

    obj = _build_obj(params)
    client.firewall.set_npt_rule(existing_uuid, obj)
    if params.get("reconfigure"):
        client.firewall.apply()
    result = client.firewall.get_npt_rule(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "firewall_npt_rule": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        log=dict(type="str", required=False, default=None),
        sequence=dict(type="str", required=False, default=None),
        interface=dict(type="str", required=False, default=None),
        source_net=dict(type="str", required=False, default=None),
        destination_net=dict(type="str", required=False, default=None),
        trackif=dict(type="str", required=False, default=None),
        categories=dict(type="str", required=False, default=None),
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
