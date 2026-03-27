#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_monit_service
short_description: Manage OPNsense Monit service checks
version_added: "0.1.0"
description:
  - Create, update, and delete Monit service checks on an OPNsense firewall via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: the module compares desired fields against the current state and
    only mutates when something differs.
options:
  state:
    description: Desired state of the service check.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing service check.
      - When provided for I(state=present), the module fetches and updates that service.
      - When provided for I(state=absent), the module deletes that service.
      - When omitted, the module searches by I(name) to locate an existing service.
    type: str
    required: false
  name:
    description:
      - Name of the Monit service check (used as the natural key when I(uuid) is omitted).
    type: str
    required: false
  enabled:
    description: Whether the service check is active.
    type: bool
    default: true
  type:
    description: Type of service check (e.g. process, host, file, filesystem, program).
    type: str
    required: false
  pidfile:
    description: Path to the PID file for process-type checks.
    type: str
    required: false
  match:
    description: Process name match pattern for process-type checks without a PID file.
    type: str
    required: false
  path:
    description: Path to file, directory, or executable for relevant check types.
    type: str
    required: false
  timeout:
    description: Timeout in seconds for the service check.
    type: int
    required: false
  starttimeout:
    description: Timeout in seconds to wait for the service to start.
    type: int
    required: false
  address:
    description: Hostname or IP address for host-type checks.
    type: str
    required: false
  interface:
    description: Network interface for network-type checks.
    type: str
    required: false
  start:
    description: Command to start the service.
    type: str
    required: false
  stop:
    description: Command to stop the service.
    type: str
    required: false
  tests:
    description: Comma-separated list of test UUIDs to associate with this service.
    type: str
    required: false
  depends:
    description: Comma-separated list of service names this service depends on.
    type: str
    required: false
  polltime:
    description: Override the global poll interval (e.g. "30" for 30 seconds).
    type: str
    required: false
  description:
    description: Human-readable description for this service check.
    type: str
    required: false
  reconfigure:
    description: Apply pending Monit changes immediately after mutating the service.
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
- name: Create a Monit process check for nginx
  opnsense.core.opnsense_monit_service:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    name: nginx
    type: process
    pidfile: /var/run/nginx.pid
    start: /usr/sbin/service nginx start
    stop: /usr/sbin/service nginx stop
    state: present
    reconfigure: true

- name: Remove a Monit service check by name
  opnsense.core.opnsense_monit_service:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    name: nginx
    state: absent
    reconfigure: true
"""

RETURN = r"""
monit_service:
  description: The Monit service check object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    name: nginx
    type: process
    pidfile: /var/run/nginx.pid
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
from opnsense_py.models.monit import MonitService

_SERVICE_FIELDS = (
    "name", "type", "pidfile", "match", "path", "timeout", "starttimeout",
    "address", "interface", "start", "stop", "tests", "depends", "polltime",
    "description",
)


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple[str, dict] | tuple[None, None]:
    try:
        svc = client.monit.get_service(uuid)
        return uuid, svc.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_name(
    client: OPNsenseClient, name: str
) -> tuple[str, dict] | tuple[None, None]:
    result = client.monit.search_services(SearchRequest(searchPhrase=name))
    for svc in result.rows:
        row = svc.model_dump()
        if row.get("name") == name:
            uuid = row.get("uuid")
            if uuid:
                return uuid, {k: v for k, v in row.items() if v is not None}
    return None, None


def _needs_update(existing: dict, params: dict) -> bool:
    for field in _SERVICE_FIELDS:
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


def _build_obj(params: dict) -> MonitService:
    enabled = params.get("enabled")
    return MonitService(
        enabled=_bool_to_api(enabled) if enabled is not None else None,
        name=params.get("name"),
        type=params.get("type"),
        pidfile=params.get("pidfile"),
        match=params.get("match"),
        path=params.get("path"),
        timeout=params.get("timeout"),
        starttimeout=params.get("starttimeout"),
        address=params.get("address"),
        interface=params.get("interface"),
        start=params.get("start"),
        stop=params.get("stop"),
        tests=params.get("tests"),
        depends=params.get("depends"),
        polltime=params.get("polltime"),
        description=params.get("description"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    name = params.get("name")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif name:
        existing_uuid, existing = _find_by_name(client, name)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.monit.del_service(existing_uuid)
            if params.get("reconfigure"):
                client.monit.reconfigure()
        return {"changed": True}

    if not name:
        raise OPNsenseError("'name' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "monit_service": None}
        svc_obj = _build_obj(params)
        response = client.monit.add_service(svc_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.monit.reconfigure()
        result = client.monit.get_service(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "monit_service": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "monit_service": existing}

    if check_mode:
        return {"changed": True, "monit_service": existing}

    svc_obj = _build_obj(params)
    client.monit.set_service(existing_uuid, svc_obj)
    if params.get("reconfigure"):
        client.monit.reconfigure()
    result = client.monit.get_service(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "monit_service": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        name=dict(type="str", required=False, default=None),
        enabled=dict(type="bool", default=True),
        type=dict(type="str", required=False, default=None),
        pidfile=dict(type="str", required=False, default=None),
        match=dict(type="str", required=False, default=None),
        path=dict(type="str", required=False, default=None),
        timeout=dict(type="int", required=False, default=None),
        starttimeout=dict(type="int", required=False, default=None),
        address=dict(type="str", required=False, default=None),
        interface=dict(type="str", required=False, default=None),
        start=dict(type="str", required=False, default=None),
        stop=dict(type="str", required=False, default=None),
        tests=dict(type="str", required=False, default=None),
        depends=dict(type="str", required=False, default=None),
        polltime=dict(type="str", required=False, default=None),
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
