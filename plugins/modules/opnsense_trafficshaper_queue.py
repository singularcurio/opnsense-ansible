#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_trafficshaper_queue
short_description: Manage OPNsense traffic shaper queues
version_added: "0.1.0"
description:
  - Create, update, and delete traffic shaper queues on an OPNsense firewall via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: the module compares desired fields against the current state and
    only mutates when something differs.
options:
  state:
    description: Desired state of the queue.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing queue.
      - When provided for I(state=present), the module fetches and updates that queue.
      - When provided for I(state=absent), the module deletes that queue.
      - When omitted, the module searches by I(description) to locate an existing queue.
    type: str
    required: false
  description:
    description:
      - Human-readable label for this queue (used as the natural key when I(uuid) is omitted).
    type: str
    required: false
  enabled:
    description: Whether the queue is active.
    type: bool
    default: true
  pipe:
    description: UUID of the parent pipe this queue belongs to.
    type: str
    required: false
  weight:
    description: Weight of the queue relative to other queues on the same pipe.
    type: int
    required: false
  mask:
    description: Dynamic queue mask (none, src-ip, dst-ip).
    type: str
    required: false
  buckets:
    description: Number of buckets for the hash table.
    type: int
    required: false
  codel_enable:
    description: Enable CoDel AQM.
    type: str
    required: false
  codel_target:
    description: CoDel target delay in ms.
    type: int
    required: false
  codel_interval:
    description: CoDel interval in ms.
    type: int
    required: false
  codel_ecn_enable:
    description: Enable ECN with CoDel.
    type: str
    required: false
  pie_enable:
    description: Enable PIE AQM.
    type: str
    required: false
  reconfigure:
    description: Apply pending traffic shaper changes immediately after mutating the queue.
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
- name: Create a traffic shaper queue on a pipe
  opnsense.core.opnsense_trafficshaper_queue:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: Bulk Traffic
    pipe: "a1b2c3d4-0000-0000-0000-000000000001"
    weight: 10
    state: present
    reconfigure: true

- name: Remove a queue by description
  opnsense.core.opnsense_trafficshaper_queue:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: Bulk Traffic
    state: absent
    reconfigure: true
"""

RETURN = r"""
trafficshaper_queue:
  description: The traffic shaper queue object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000002"
    description: Bulk Traffic
    pipe: "a1b2c3d4-0000-0000-0000-000000000001"
    weight: 10
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
from opnsense_py.models.trafficshaper import ShaperQueue

_QUEUE_FIELDS = (
    "pipe", "weight", "mask", "buckets",
    "codel_enable", "codel_target", "codel_interval", "codel_ecn_enable",
    "pie_enable", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple[str, dict] | tuple[None, None]:
    try:
        queue = client.trafficshaper.get_queue(uuid)
        return uuid, queue.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(
    client: OPNsenseClient, description: str
) -> tuple[str, dict] | tuple[None, None]:
    result = client.trafficshaper.search_queues(SearchRequest(searchPhrase=description))
    for queue in result.rows:
        row = queue.model_dump()
        if row.get("description") == description:
            uuid = row.get("uuid")
            if uuid:
                return uuid, {k: v for k, v in row.items() if v is not None}
    return None, None


def _needs_update(existing: dict, params: dict) -> bool:
    for field in _QUEUE_FIELDS:
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


def _build_obj(params: dict) -> ShaperQueue:
    enabled = params.get("enabled")
    return ShaperQueue(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        pipe=params.get("pipe"),
        weight=params.get("weight"),
        mask=params.get("mask"),
        buckets=params.get("buckets"),
        codel_enable=params.get("codel_enable"),
        codel_target=params.get("codel_target"),
        codel_interval=params.get("codel_interval"),
        codel_ecn_enable=params.get("codel_ecn_enable"),
        pie_enable=params.get("pie_enable"),
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
            client.trafficshaper.del_queue(existing_uuid)
            if params.get("reconfigure"):
                client.trafficshaper.reconfigure()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "trafficshaper_queue": None}
        queue_obj = _build_obj(params)
        response = client.trafficshaper.add_queue(queue_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.trafficshaper.reconfigure()
        result = client.trafficshaper.get_queue(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "trafficshaper_queue": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "trafficshaper_queue": existing}

    if check_mode:
        return {"changed": True, "trafficshaper_queue": existing}

    queue_obj = _build_obj(params)
    client.trafficshaper.set_queue(existing_uuid, queue_obj)
    if params.get("reconfigure"):
        client.trafficshaper.reconfigure()
    result = client.trafficshaper.get_queue(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "trafficshaper_queue": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        pipe=dict(type="str", required=False, default=None),
        weight=dict(type="int", required=False, default=None),
        mask=dict(type="str", required=False, default=None),
        buckets=dict(type="int", required=False, default=None),
        codel_enable=dict(type="str", required=False, default=None),
        codel_target=dict(type="int", required=False, default=None),
        codel_interval=dict(type="int", required=False, default=None),
        codel_ecn_enable=dict(type="str", required=False, default=None),
        pie_enable=dict(type="str", required=False, default=None),
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
