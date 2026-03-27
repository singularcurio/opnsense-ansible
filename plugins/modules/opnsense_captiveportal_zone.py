#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_captiveportal_zone
short_description: Manage OPNsense captive portal zones
version_added: "0.1.0"
description:
  - Create, update, and delete captive portal zones on an OPNsense firewall via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: the module compares desired fields against the current state and
    only mutates when something differs.
options:
  state:
    description: Desired state of the captive portal zone.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing captive portal zone.
      - When provided for I(state=present), the module fetches and updates that zone.
      - When provided for I(state=absent), the module deletes that zone.
      - When omitted, the module searches by I(description) to locate an existing zone.
    type: str
    required: false
  description:
    description: Human-readable label for this zone. Used as natural key.
    type: str
    required: false
  enabled:
    description: Whether the zone is active.
    type: bool
    default: true
  zoneid:
    description: Zone ID number.
    type: str
    required: false
  interfaces:
    description: Network interfaces assigned to this zone.
    type: str
    required: false
  authservers:
    description: Authentication servers for this zone.
    type: str
    required: false
  idletimeout:
    description: Idle timeout in minutes (0 = disabled).
    type: str
    required: false
  hardtimeout:
    description: Hard timeout in minutes (0 = disabled).
    type: str
    required: false
  concurrentlogins:
    description: Allow concurrent logins from the same user.
    type: str
    required: false
  bandwidth_up:
    description: Upload bandwidth limit in Kbps (0 = unlimited).
    type: str
    required: false
  bandwidth_down:
    description: Download bandwidth limit in Kbps (0 = unlimited).
    type: str
    required: false
  reconfigure:
    description: Apply captive portal changes immediately after mutating the zone.
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
- name: Create a guest WiFi captive portal zone
  opnsense.core.opnsense_captiveportal_zone:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: Guest WiFi
    interfaces: opt1
    hardtimeout: "480"
    state: present
    reconfigure: true

- name: Remove a captive portal zone
  opnsense.core.opnsense_captiveportal_zone:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: Guest WiFi
    state: absent
    reconfigure: true
"""

RETURN = r"""
captiveportal_zone:
  description: The captive portal zone object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    description: Guest WiFi
    enabled: "1"
    interfaces: opt1
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
from opnsense_py.models.captiveportal import CaptivePortalZone

_FIELDS = (
    "zoneid", "interfaces", "authservers", "idletimeout", "hardtimeout",
    "concurrentlogins", "bandwidth_up", "bandwidth_down", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.captiveportal.get_zone(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(client: OPNsenseClient, description: str):
    result = client.captiveportal.search_zones(SearchRequest(searchPhrase=description))
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


def _build_obj(params: dict) -> CaptivePortalZone:
    enabled = params.get("enabled")
    return CaptivePortalZone(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        zoneid=params.get("zoneid"),
        interfaces=params.get("interfaces"),
        authservers=params.get("authservers"),
        idletimeout=params.get("idletimeout"),
        hardtimeout=params.get("hardtimeout"),
        concurrentlogins=params.get("concurrentlogins"),
        bandwidth_up=params.get("bandwidth_up"),
        bandwidth_down=params.get("bandwidth_down"),
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
            client.captiveportal.del_zone(existing_uuid)
            if params.get("reconfigure"):
                client.captiveportal.reconfigure()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "captiveportal_zone": None}
        obj = _build_obj(params)
        response = client.captiveportal.add_zone(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.captiveportal.reconfigure()
        result = client.captiveportal.get_zone(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "captiveportal_zone": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "captiveportal_zone": existing}

    if check_mode:
        return {"changed": True, "captiveportal_zone": existing}

    obj = _build_obj(params)
    client.captiveportal.set_zone(existing_uuid, obj)
    if params.get("reconfigure"):
        client.captiveportal.reconfigure()
    result = client.captiveportal.get_zone(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "captiveportal_zone": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        zoneid=dict(type="str", required=False, default=None),
        interfaces=dict(type="str", required=False, default=None),
        authservers=dict(type="str", required=False, default=None),
        idletimeout=dict(type="str", required=False, default=None),
        hardtimeout=dict(type="str", required=False, default=None),
        concurrentlogins=dict(type="str", required=False, default=None),
        bandwidth_up=dict(type="str", required=False, default=None),
        bandwidth_down=dict(type="str", required=False, default=None),
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
