#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_trafficshaper_rule
short_description: Manage OPNsense traffic shaper rules
version_added: "0.1.0"
description:
  - Create, update, and delete traffic shaper rules on an OPNsense firewall via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: the module compares desired fields against the current state and
    only mutates when something differs.
options:
  state:
    description: Desired state of the rule.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing rule.
      - When provided for I(state=present), the module fetches and updates that rule.
      - When provided for I(state=absent), the module deletes that rule.
      - When omitted, the module searches by I(description) to locate an existing rule.
    type: str
    required: false
  description:
    description:
      - Human-readable label for this rule (used as the natural key when I(uuid) is omitted).
    type: str
    required: false
  enabled:
    description: Whether the rule is active.
    type: bool
    default: true
  sequence:
    description: Order of the rule relative to others (lower numbers evaluated first).
    type: int
    required: false
  interface:
    description: Source interface the rule applies to.
    type: str
    required: false
  interface2:
    description: Optional second interface for bidirectional rules.
    type: str
    required: false
  proto:
    description: Protocol the rule matches (e.g. ip, tcp, udp, icmp).
    type: str
    required: false
  iplen:
    description: IP packet length to match.
    type: int
    required: false
  source:
    description: Source network or host address.
    type: str
    required: false
  source_not:
    description: Invert source match.
    type: str
    required: false
  src_port:
    description: Source port or port range.
    type: str
    required: false
  destination:
    description: Destination network or host address.
    type: str
    required: false
  destination_not:
    description: Invert destination match.
    type: str
    required: false
  dst_port:
    description: Destination port or port range.
    type: str
    required: false
  dscp:
    description: DSCP value to match.
    type: str
    required: false
  direction:
    description: Traffic direction (in or out).
    type: str
    required: false
  target:
    description: UUID of the pipe or queue to assign matched traffic to.
    type: str
    required: false
  reconfigure:
    description: Apply pending traffic shaper changes immediately after mutating the rule.
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
- name: Create a traffic shaper rule
  opnsense.core.opnsense_trafficshaper_rule:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    description: Shape HTTP traffic
    interface: wan
    proto: tcp
    dst_port: "80"
    target: "a1b2c3d4-0000-0000-0000-000000000001"
    state: present
    reconfigure: true

- name: Remove a rule by description
  opnsense.core.opnsense_trafficshaper_rule:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    description: Shape HTTP traffic
    state: absent
    reconfigure: true
"""

RETURN = r"""
trafficshaper_rule:
  description: The traffic shaper rule object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000003"
    description: Shape HTTP traffic
    interface: wan
    proto: tcp
    dst_port: "80"
    target: "a1b2c3d4-0000-0000-0000-000000000001"
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
from opnsense_py.models.trafficshaper import ShaperRule

_RULE_FIELDS = (
    "sequence", "interface", "interface2", "proto", "iplen",
    "source", "source_not", "src_port",
    "destination", "destination_not", "dst_port",
    "dscp", "direction", "target", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple[str, dict] | tuple[None, None]:
    try:
        rule = client.trafficshaper.get_rule(uuid)
        return uuid, rule.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_description(
    client: OPNsenseClient, description: str
) -> tuple[str, dict] | tuple[None, None]:
    result = client.trafficshaper.search_rules(SearchRequest(searchPhrase=description))
    for rule in result.rows:
        row = rule.model_dump()
        if row.get("description") == description:
            uuid = row.get("uuid")
            if uuid:
                return uuid, {k: v for k, v in row.items() if v is not None}
    return None, None


def _needs_update(existing: dict, params: dict) -> bool:
    for field in _RULE_FIELDS:
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


def _build_obj(params: dict) -> ShaperRule:
    enabled = params.get("enabled")
    return ShaperRule(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        sequence=params.get("sequence"),
        interface=params.get("interface"),
        interface2=params.get("interface2"),
        proto=params.get("proto"),
        iplen=params.get("iplen"),
        source=params.get("source"),
        source_not=params.get("source_not"),
        src_port=params.get("src_port"),
        destination=params.get("destination"),
        destination_not=params.get("destination_not"),
        dst_port=params.get("dst_port"),
        dscp=params.get("dscp"),
        direction=params.get("direction"),
        target=params.get("target"),
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
            client.trafficshaper.del_rule(existing_uuid)
            if params.get("reconfigure"):
                client.trafficshaper.reconfigure()
        return {"changed": True}

    if not description:
        raise OPNsenseError("'description' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "trafficshaper_rule": None}
        rule_obj = _build_obj(params)
        response = client.trafficshaper.add_rule(rule_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.trafficshaper.reconfigure()
        result = client.trafficshaper.get_rule(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "trafficshaper_rule": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "trafficshaper_rule": existing}

    if check_mode:
        return {"changed": True, "trafficshaper_rule": existing}

    rule_obj = _build_obj(params)
    client.trafficshaper.set_rule(existing_uuid, rule_obj)
    if params.get("reconfigure"):
        client.trafficshaper.reconfigure()
    result = client.trafficshaper.get_rule(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "trafficshaper_rule": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        sequence=dict(type="int", required=False, default=None),
        interface=dict(type="str", required=False, default=None),
        interface2=dict(type="str", required=False, default=None),
        proto=dict(type="str", required=False, default=None),
        iplen=dict(type="int", required=False, default=None),
        source=dict(type="str", required=False, default=None),
        source_not=dict(type="str", required=False, default=None),
        src_port=dict(type="str", required=False, default=None),
        destination=dict(type="str", required=False, default=None),
        destination_not=dict(type="str", required=False, default=None),
        dst_port=dict(type="str", required=False, default=None),
        dscp=dict(type="str", required=False, default=None),
        direction=dict(type="str", required=False, default=None),
        target=dict(type="str", required=False, default=None),
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
