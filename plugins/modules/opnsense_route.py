#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_route
short_description: Manage OPNsense static routes
version_added: "0.1.0"
description:
  - Create, update, and delete static routes on an OPNsense firewall via the REST API.
  - Changes are staged until reconfigured; set I(reconfigure=true) to apply immediately.
  - Idempotent: compares desired fields against the current state and only mutates when something differs.
  - Natural key is the I(network) field.
options:
  state:
    description: Desired state of the route.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing route.
      - When omitted, the module searches by I(network).
    type: str
    required: false
  network:
    description:
      - Destination network in CIDR notation (required for I(state=present) when I(uuid) is not given).
      - Used as the search key.
    type: str
    required: false
  gateway:
    description: Gateway name or IP address for this route.
    type: str
    required: false
  descr:
    description: Human-readable description for this route.
    type: str
    required: false
  enabled:
    description:
      - Whether the route is active. Maps to the API C(disabled) field (inverted).
    type: bool
    default: true
  reconfigure:
    description: Apply pending route changes immediately after mutating.
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
- name: Add a static route
  opnsense.core.opnsense_route:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    network: 10.0.0.0/8
    gateway: WAN_DHCP
    descr: Corporate network
    state: present
    reconfigure: true

- name: Disable a static route
  opnsense.core.opnsense_route:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    network: 10.0.0.0/8
    enabled: false
    state: present

- name: Remove a static route
  opnsense.core.opnsense_route:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    network: 10.0.0.0/8
    state: absent
    reconfigure: true
"""

RETURN = r"""
route:
  description: The route object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    network: 10.0.0.0/8
    gateway: WAN_DHCP
    disabled: "0"
    descr: Corporate network
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
from opnsense_py.models.routes import Route

_FIELDS = ("network", "gateway", "descr")


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple:
    try:
        route = client.routes.get_route(uuid)
        return uuid, route.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_network(client: OPNsenseClient, network: str) -> tuple:
    result = client.routes.search_routes(SearchRequest(searchPhrase=network))
    for route in result.rows:
        row = route.model_dump()
        if row.get("network") == network:
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
    # enabled param maps to the inverted "disabled" API field
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        desired_disabled = "1" if not desired_enabled else "0"
        if existing.get("disabled") != desired_disabled:
            return True
    return False


def _build_obj(params: dict) -> Route:
    enabled = params.get("enabled")
    disabled = "1" if not enabled else "0"
    return Route(
        network=params.get("network"),
        gateway=params.get("gateway"),
        descr=params.get("descr"),
        disabled=disabled,
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    network = params.get("network")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif network:
        existing_uuid, existing = _find_by_network(client, network)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.routes.del_route(existing_uuid)
            if params.get("reconfigure"):
                client.routes.reconfigure()
        return {"changed": True}

    if not network:
        raise OPNsenseError("'network' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "route": None}
        route_obj = _build_obj(params)
        response = client.routes.add_route(route_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.routes.reconfigure()
        result = client.routes.get_route(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "route": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "route": existing}

    if check_mode:
        return {"changed": True, "route": existing}

    route_obj = _build_obj(params)
    client.routes.set_route(existing_uuid, route_obj)
    if params.get("reconfigure"):
        client.routes.reconfigure()
    result = client.routes.get_route(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "route": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        network=dict(type="str", required=False, default=None),
        gateway=dict(type="str", required=False, default=None),
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
