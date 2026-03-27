#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_ipsec_child
short_description: Manage IPsec child SA (tunnel) definitions
version_added: "0.1.0"
description:
  - Create, update, and delete IPsec child SA definitions on an OPNsense firewall.
  - Natural key is the I(description) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the IPsec child SA.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing IPsec child SA.
    type: str
    required: false
  description:
    description: Child SA description. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the child SA is active.
    type: bool
    default: true
  connection:
    description: UUID of the parent IPsec connection.
    type: str
    required: false
  reqid:
    description: Request ID for the child SA.
    type: int
    required: false
  esp_proposals:
    description: ESP proposals for the child SA.
    type: str
    required: false
  sha256_96:
    description: Use 96-bit SHA-256 truncation.
    type: str
    required: false
  start_action:
    description: Action on startup (start, trap, none).
    type: str
    required: false
  close_action:
    description: Action on close (restart, trap, none).
    type: str
    required: false
  dpd_action:
    description: DPD action (restart, trap, clear, none).
    type: str
    required: false
  mode:
    description: IPsec mode (tunnel, transport, beet, pass, drop).
    type: str
    required: false
  policies:
    description: Install policies for the child SA.
    type: str
    required: false
  local_ts:
    description: Local traffic selectors.
    type: str
    required: false
  remote_ts:
    description: Remote traffic selectors.
    type: str
    required: false
  rekey_time:
    description: Rekey interval in seconds.
    type: int
    required: false
  reconfigure:
    description: Apply IPsec changes immediately after mutating the child SA.
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
- name: Create an IPsec child SA
  opnsense.core.opnsense_ipsec_child:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: Child SA tunnel
    mode: tunnel
    local_ts: "10.0.0.0/24"
    remote_ts: "10.1.0.0/24"
    state: present
    reconfigure: true

- name: Remove an IPsec child SA
  opnsense.core.opnsense_ipsec_child:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: Child SA tunnel
    state: absent
    reconfigure: true
"""

RETURN = r"""
ipsec_child:
  description: The IPsec child SA object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    description: Child SA tunnel
    enabled: "1"
    mode: tunnel
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
from opnsense_py.models.ipsec import IPsecChild

_FIELDS = (
    "connection", "reqid", "esp_proposals", "sha256_96", "start_action",
    "close_action", "dpd_action", "mode", "policies", "local_ts", "remote_ts",
    "rekey_time", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.ipsec.get_child(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(client: OPNsenseClient, description: str):
    result = client.ipsec.search_children(SearchRequest(searchPhrase=description))
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


def _build_obj(params: dict) -> IPsecChild:
    enabled = params.get("enabled")
    return IPsecChild(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        connection=params.get("connection"),
        reqid=params.get("reqid"),
        esp_proposals=params.get("esp_proposals"),
        sha256_96=params.get("sha256_96"),
        start_action=params.get("start_action"),
        close_action=params.get("close_action"),
        dpd_action=params.get("dpd_action"),
        mode=params.get("mode"),
        policies=params.get("policies"),
        local_ts=params.get("local_ts"),
        remote_ts=params.get("remote_ts"),
        rekey_time=params.get("rekey_time"),
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
            client.ipsec.del_child(existing_uuid)
            if params.get("reconfigure"):
                client.ipsec.reconfigure()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "ipsec_child": None}
        obj = _build_obj(params)
        response = client.ipsec.add_child(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.ipsec.reconfigure()
        result = client.ipsec.get_child(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "ipsec_child": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "ipsec_child": existing}

    if check_mode:
        return {"changed": True, "ipsec_child": existing}

    obj = _build_obj(params)
    client.ipsec.set_child(existing_uuid, obj)
    if params.get("reconfigure"):
        client.ipsec.reconfigure()
    result = client.ipsec.get_child(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "ipsec_child": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        connection=dict(type="str", required=False, default=None),
        reqid=dict(type="int", required=False, default=None),
        esp_proposals=dict(type="str", required=False, default=None),
        sha256_96=dict(type="str", required=False, default=None),
        start_action=dict(type="str", required=False, default=None),
        close_action=dict(type="str", required=False, default=None),
        dpd_action=dict(type="str", required=False, default=None),
        mode=dict(type="str", required=False, default=None),
        policies=dict(type="str", required=False, default=None),
        local_ts=dict(type="str", required=False, default=None),
        remote_ts=dict(type="str", required=False, default=None),
        rekey_time=dict(type="int", required=False, default=None),
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
