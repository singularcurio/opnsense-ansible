#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_monit_alert
short_description: Manage OPNsense Monit email alerts
version_added: "0.1.0"
description:
  - Create, update, and delete Monit email alert definitions on an OPNsense firewall
    via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: the module compares desired fields against the current state and
    only mutates when something differs.
options:
  state:
    description: Desired state of the alert.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing alert.
      - When provided for I(state=present), the module fetches and updates that alert.
      - When provided for I(state=absent), the module deletes that alert.
      - When omitted, the module searches by I(recipient) to locate an existing alert.
    type: str
    required: false
  recipient:
    description:
      - Email address of the alert recipient (used as the natural key when I(uuid) is omitted).
    type: str
    required: false
  enabled:
    description: Whether the alert is active.
    type: bool
    default: true
  noton:
    description: Invert the event filter (alert on all events except those listed).
    type: str
    required: false
  events:
    description: Comma-separated list of Monit events that trigger this alert.
    type: str
    required: false
  format:
    description: Custom mail format string for the alert message.
    type: str
    required: false
  reminder:
    description: Send a reminder every N cycles if the condition persists.
    type: int
    required: false
  description:
    description: Human-readable description for this alert.
    type: str
    required: false
  reconfigure:
    description: Apply pending Monit changes immediately after mutating the alert.
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
- name: Create a Monit alert for admin
  opnsense.core.opnsense_monit_alert:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    recipient: admin@example.com
    events: "failure,timeout,stopped"
    reminder: 10
    state: present
    reconfigure: true

- name: Remove a Monit alert by recipient
  opnsense.core.opnsense_monit_alert:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    recipient: admin@example.com
    state: absent
    reconfigure: true
"""

RETURN = r"""
monit_alert:
  description: The Monit alert object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    recipient: admin@example.com
    events: "failure,timeout,stopped"
    reminder: 10
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
from opnsense_py.models.monit import MonitAlert

_ALERT_FIELDS = ("recipient", "noton", "events", "format", "reminder", "description")


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple[str, dict] | tuple[None, None]:
    try:
        alert = client.monit.get_alert(uuid)
        return uuid, alert.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_recipient(
    client: OPNsenseClient, recipient: str
) -> tuple[str, dict] | tuple[None, None]:
    result = client.monit.search_alerts(SearchRequest(searchPhrase=recipient))
    for alert in result.rows:
        row = alert.model_dump()
        if row.get("recipient") == recipient:
            uuid = row.get("uuid")
            if uuid:
                return uuid, {k: v for k, v in row.items() if v is not None}
    return None, None


def _needs_update(existing: dict, params: dict) -> bool:
    for field in _ALERT_FIELDS:
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


def _build_obj(params: dict) -> MonitAlert:
    enabled = params.get("enabled")
    return MonitAlert(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        recipient=params.get("recipient"),
        noton=params.get("noton"),
        events=params.get("events"),
        format=params.get("format"),
        reminder=params.get("reminder"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    recipient = params.get("recipient")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif recipient:
        existing_uuid, existing = _find_by_recipient(client, recipient)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.monit.del_alert(existing_uuid)
            if params.get("reconfigure"):
                client.monit.reconfigure()
        return {"changed": True}

    if not recipient:
        raise OPNsenseError("'recipient' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "monit_alert": None}
        alert_obj = _build_obj(params)
        response = client.monit.add_alert(alert_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.monit.reconfigure()
        result = client.monit.get_alert(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "monit_alert": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "monit_alert": existing}

    if check_mode:
        return {"changed": True, "monit_alert": existing}

    alert_obj = _build_obj(params)
    client.monit.set_alert(existing_uuid, alert_obj)
    if params.get("reconfigure"):
        client.monit.reconfigure()
    result = client.monit.get_alert(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "monit_alert": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        recipient=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        noton=dict(type="str", required=False, default=None),
        events=dict(type="str", required=False, default=None),
        format=dict(type="str", required=False, default=None),
        reminder=dict(type="int", required=False, default=None),
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
