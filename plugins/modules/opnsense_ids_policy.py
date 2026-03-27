#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_ids_policy
short_description: Manage OPNsense IDS/IPS policies
version_added: "0.1.0"
description:
  - Create, update, and delete IDS/IPS policies on an OPNsense firewall via the REST API.
  - Natural key is the I(description) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the IDS policy.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing IDS policy.
    type: str
    required: false
  description:
    description: Policy description. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the policy is active.
    type: bool
    default: true
  prio:
    description: Policy priority.
    type: int
    required: false
  action:
    description: Policy action (alert, drop, pass).
    type: str
    required: false
  rulesets:
    description: Rulesets to apply this policy to.
    type: str
    required: false
  content:
    description: Content filter expression.
    type: str
    required: false
  new_action:
    description: New action to apply to matching rules.
    type: str
    required: false
  reconfigure:
    description: Apply IDS changes immediately after mutating the policy.
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
- name: Create an IDS policy
  opnsense.core.opnsense_ids_policy:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: Block known malware
    action: alert
    new_action: drop
    state: present
    reconfigure: true

- name: Remove an IDS policy
  opnsense.core.opnsense_ids_policy:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: Block known malware
    state: absent
    reconfigure: true
"""

RETURN = r"""
ids_policy:
  description: The IDS policy object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    description: Block known malware
    enabled: "1"
    action: alert
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
from opnsense_py.models.ids import IDSPolicy

_FIELDS = ("prio", "action", "rulesets", "content", "new_action", "description")


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.ids.get_policy(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(client: OPNsenseClient, description: str):
    result = client.ids.search_policies(SearchRequest(searchPhrase=description))
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


def _build_obj(params: dict) -> IDSPolicy:
    enabled = params.get("enabled")
    return IDSPolicy(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        prio=params.get("prio"),
        action=params.get("action"),
        rulesets=params.get("rulesets"),
        content=params.get("content"),
        new_action=params.get("new_action"),
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
            client.ids.del_policy(existing_uuid)
            if params.get("reconfigure"):
                client.ids.reconfigure()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "ids_policy": None}
        obj = _build_obj(params)
        response = client.ids.add_policy(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.ids.reconfigure()
        result = client.ids.get_policy(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "ids_policy": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "ids_policy": existing}

    if check_mode:
        return {"changed": True, "ids_policy": existing}

    obj = _build_obj(params)
    client.ids.set_policy(existing_uuid, obj)
    if params.get("reconfigure"):
        client.ids.reconfigure()
    result = client.ids.get_policy(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "ids_policy": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        prio=dict(type="int", required=False, default=None),
        action=dict(type="str", required=False, default=None),
        rulesets=dict(type="str", required=False, default=None),
        content=dict(type="str", required=False, default=None),
        new_action=dict(type="str", required=False, default=None),
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
