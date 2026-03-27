#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_syslog_destination
short_description: Manage OPNsense syslog remote destinations
version_added: "0.1.0"
description:
  - Create, update, and delete syslog remote destination entries on an OPNsense firewall.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: compares desired fields against the current state and only mutates when something differs.
  - Natural key is the I(hostname) field.
options:
  state:
    description: Desired state of the syslog destination.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing syslog destination.
      - When omitted, the module searches by I(hostname).
    type: str
    required: false
  enabled:
    description: Whether the syslog destination is active.
    type: bool
    default: true
  transport:
    description: Transport protocol (udp4, tcp4, tls4, udp6, tcp6, tls6).
    type: str
    required: false
  program:
    description: Program/application filter.
    type: str
    required: false
  level:
    description: Syslog severity level filter.
    type: str
    required: false
  facility:
    description: Syslog facility filter.
    type: str
    required: false
  hostname:
    description:
      - Remote syslog server hostname or IP (required for I(state=present) when I(uuid) is not given).
      - Used as the search key.
    type: str
    required: false
  certificate:
    description: TLS certificate UUID for encrypted transport.
    type: str
    required: false
  syslog_port:
    description: Remote syslog server port (maps to the API C(port) field).
    type: str
    required: false
  rfc5424:
    description: Use RFC 5424 log format.
    type: str
    required: false
  description:
    description: Human-readable description.
    type: str
    required: false
  reconfigure:
    description: Apply pending syslog changes immediately after mutating.
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
    description: Override the default OPNsense API port (443 for HTTPS, 80 for HTTP).
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
- name: Add a remote syslog destination
  opnsense.core.opnsense_syslog_destination:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    hostname: syslog.example.com
    transport: udp4
    syslog_port: "514"
    level: info
    description: Central syslog server
    state: present
    reconfigure: true

- name: Remove a syslog destination
  opnsense.core.opnsense_syslog_destination:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    hostname: syslog.example.com
    state: absent
    reconfigure: true
"""

RETURN = r"""
syslog_destination:
  description: The syslog destination object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    hostname: syslog.example.com
    transport: udp4
    port: "514"
    level: info
    enabled: "1"
    description: Central syslog server
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
from opnsense_py.models.syslog import SyslogDestination

_FIELDS = (
    "transport", "program", "level", "facility", "hostname",
    "certificate", "rfc5424", "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple:
    try:
        dest = client.syslog.get_destination(uuid)
        return uuid, dest.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_hostname(client: OPNsenseClient, hostname: str) -> tuple:
    result = client.syslog.search_destinations(SearchRequest(searchPhrase=hostname))
    for dest in result.rows:
        row = dest.model_dump()
        if row.get("hostname") == hostname:
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
    # syslog_port maps to the API "port" field
    desired_syslog_port = params.get("syslog_port")
    if desired_syslog_port is not None:
        if existing.get("port") != desired_syslog_port:
            return True
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("enabled") != _bool_to_api(desired_enabled):
            return True
    return False


def _build_obj(params: dict) -> SyslogDestination:
    enabled = params.get("enabled")
    return SyslogDestination(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        transport=params.get("transport"),
        program=params.get("program"),
        level=params.get("level"),
        facility=params.get("facility"),
        hostname=params.get("hostname"),
        certificate=params.get("certificate"),
        port=params.get("syslog_port"),
        rfc5424=params.get("rfc5424"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    hostname = params.get("hostname")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif hostname:
        existing_uuid, existing = _find_by_hostname(client, hostname)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.syslog.del_destination(existing_uuid)
            if params.get("reconfigure"):
                client.syslog.reconfigure()
        return {"changed": True}

    if not hostname:
        raise OPNsenseError("'hostname' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "syslog_destination": None}
        dest_obj = _build_obj(params)
        response = client.syslog.add_destination(dest_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.syslog.reconfigure()
        result = client.syslog.get_destination(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "syslog_destination": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "syslog_destination": existing}

    if check_mode:
        return {"changed": True, "syslog_destination": existing}

    dest_obj = _build_obj(params)
    client.syslog.set_destination(existing_uuid, dest_obj)
    if params.get("reconfigure"):
        client.syslog.reconfigure()
    result = client.syslog.get_destination(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "syslog_destination": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        transport=dict(type="str", required=False, default=None),
        program=dict(type="str", required=False, default=None),
        level=dict(type="str", required=False, default=None),
        facility=dict(type="str", required=False, default=None),
        hostname=dict(type="str", required=False, default=None),
        certificate=dict(type="str", required=False, default=None),
        syslog_port=dict(type="str", required=False, default=None),
        rfc5424=dict(type="str", required=False, default=None),
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
