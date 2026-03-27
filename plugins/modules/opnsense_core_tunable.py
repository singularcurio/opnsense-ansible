#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_core_tunable
short_description: Manage OPNsense sysctl tunables
version_added: "0.1.0"
description:
  - Create, update, and delete sysctl tunable overrides on an OPNsense firewall
    via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: the module compares desired fields against the current state and
    only mutates when something differs.
options:
  state:
    description: Desired state of the tunable.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing tunable.
      - When provided for I(state=present), the module fetches and updates that tunable.
      - When provided for I(state=absent), the module deletes that tunable.
      - When omitted, the module searches by I(tunable) to locate an existing entry.
    type: str
    required: false
  tunable:
    description:
      - Sysctl name (e.g. C(net.inet.ip.forwarding)).
        Used as the natural key when I(uuid) is omitted.
    type: str
    required: false
  value:
    description: Value to set for the tunable.
    type: str
    required: false
  descr:
    description: Human-readable description for this tunable.
    type: str
    required: false
  enabled:
    description: Whether the tunable override is active.
    type: bool
    default: true
  reconfigure:
    description: Apply pending tunable changes immediately after mutating the entry.
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
- name: Enable IP forwarding
  opnsense.core.opnsense_core_tunable:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    tunable: net.inet.ip.forwarding
    value: "1"
    descr: Enable IPv4 forwarding
    state: present
    reconfigure: true

- name: Remove a tunable override
  opnsense.core.opnsense_core_tunable:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    tunable: net.inet.ip.forwarding
    state: absent
    reconfigure: true
"""

RETURN = r"""
core_tunable:
  description: The tunable object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    tunable: net.inet.ip.forwarding
    value: "1"
    descr: Enable IPv4 forwarding
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

_TUNABLE_FIELDS = ("tunable", "value", "descr")


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple[str, dict] | tuple[None, None]:
    try:
        raw = client.core.get_tunable(uuid)
        data = raw.get("tunable", raw)
        return uuid, {k: v for k, v in data.items() if v is not None}
    except OPNsenseNotFoundError:
        return None, None


def _find_by_tunable(
    client: OPNsenseClient, tunable_name: str
) -> tuple[str, dict] | tuple[None, None]:
    result = client.core.search_tunables(SearchRequest(searchPhrase=tunable_name))
    for row in result.rows:
        data = row.model_dump()
        if data.get("tunable") == tunable_name:
            uuid = data.get("uuid")
            if uuid:
                return uuid, {k: v for k, v in data.items() if v is not None}
    return None, None


def _needs_update(existing: dict, params: dict) -> bool:
    for field in _TUNABLE_FIELDS:
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


def _build_obj(params: dict) -> dict:
    enabled = params.get("enabled")
    return {
        "tunable": {
            "tunable": params.get("tunable"),
            "value": params.get("value"),
            "descr": params.get("descr"),
            "enabled": _bool_to_api(enabled) if enabled is not None else None,
        }
    }


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    tunable_name = params.get("tunable")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif tunable_name:
        existing_uuid, existing = _find_by_tunable(client, tunable_name)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.core.del_tunable(existing_uuid)
            if params.get("reconfigure"):
                client.core.reconfigure_tunables()
        return {"changed": True}

    if not tunable_name:
        raise OPNsenseError("'tunable' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "core_tunable": None}
        data = _build_obj(params)
        response = client.core.add_tunable(data)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.core.reconfigure_tunables()
        raw = client.core.get_tunable(new_uuid)
        result = raw.get("tunable", raw)
        result = {k: v for k, v in result.items() if v is not None}
        result["uuid"] = new_uuid
        return {"changed": True, "core_tunable": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "core_tunable": existing}

    if check_mode:
        return {"changed": True, "core_tunable": existing}

    data = _build_obj(params)
    client.core.set_tunable(existing_uuid, data)
    if params.get("reconfigure"):
        client.core.reconfigure_tunables()
    raw = client.core.get_tunable(existing_uuid)
    result = raw.get("tunable", raw)
    result = {k: v for k, v in result.items() if v is not None}
    result["uuid"] = existing_uuid
    return {"changed": True, "core_tunable": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        tunable=dict(type="str", required=False, default=None),
        value=dict(type="str", required=False, default=None),
        descr=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
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
