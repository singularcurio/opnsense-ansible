#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_dnsmasq_host
short_description: Manage Dnsmasq host overrides
version_added: "0.1.0"
description:
  - Create, update, and delete Dnsmasq host overrides on an OPNsense firewall.
  - Natural key is the composite of I(host) and I(domain).
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the host override.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing host override.
    type: str
    required: false
  host:
    description: Hostname part of the override. Used as part of the composite natural key.
    type: str
    required: false
  domain:
    description: Domain part of the override. Used as part of the composite natural key.
    type: str
    required: false
  local:
    description: Local DNS zone.
    type: str
    required: false
  ip:
    description: IP address for this host.
    type: str
    required: false
  cnames:
    description: Additional hostnames (CNAMEs).
    type: str
    required: false
  client_id:
    description: DHCP client identifier.
    type: str
    required: false
  hwaddr:
    description: Hardware (MAC) address for static DHCP mapping.
    type: str
    required: false
  lease_time:
    description: DHCP lease time in seconds.
    type: int
    required: false
  ignore:
    description: Ignore DHCP requests from this host.
    type: str
    required: false
  descr:
    description: Human-readable description.
    type: str
    required: false
  comments:
    description: Additional comments.
    type: str
    required: false
  reconfigure:
    description: Apply pending Dnsmasq changes immediately.
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
    description: Verify TLS certificate.
    type: bool
    required: false
  port:
    description: Override the default port.
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
- name: Create a Dnsmasq host override
  opnsense.core.opnsense_dnsmasq_host:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    host: "myserver"
    domain: "example.com"
    ip: "192.168.1.50"
    state: present
    reconfigure: true

- name: Remove a Dnsmasq host override
  opnsense.core.opnsense_dnsmasq_host:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    host: "myserver"
    domain: "example.com"
    state: absent
"""

RETURN = r"""
dnsmasq_host:
  description: The Dnsmasq host override object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    host: "myserver"
    domain: "example.com"
    ip: "192.168.1.50"
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
from opnsense_py.models.dnsmasq import DnsmasqHost

_FIELDS = (
    "host", "domain", "local", "ip", "cnames", "client_id",
    "hwaddr", "lease_time", "ignore", "descr", "comments",
)


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.dnsmasq.get_host(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_host_domain(client: OPNsenseClient, host: str, domain: str):
    result = client.dnsmasq.search_hosts(SearchRequest(searchPhrase=host))
    for item in result.rows:
        row = item.model_dump()
        if row.get("host") == host and row.get("domain") == domain:
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
    return False


def _build_obj(params: dict) -> DnsmasqHost:
    return DnsmasqHost(
        host=params.get("host"),
        domain=params.get("domain"),
        local=params.get("local"),
        ip=params.get("ip"),
        cnames=params.get("cnames"),
        client_id=params.get("client_id"),
        hwaddr=params.get("hwaddr"),
        lease_time=params.get("lease_time"),
        ignore=params.get("ignore"),
        descr=params.get("descr"),
        comments=params.get("comments"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    host = params.get("host")
    domain = params.get("domain")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif host and domain is not None:
        existing_uuid, existing = _find_by_host_domain(client, host, domain)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.dnsmasq.del_host(existing_uuid)
            if params.get("reconfigure"):
                client.dnsmasq.reconfigure()
        return {"changed": True}

    if not host or domain is None:
        raise OPNsenseError("'host' and 'domain' are required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "dnsmasq_host": None}
        obj = _build_obj(params)
        response = client.dnsmasq.add_host(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.dnsmasq.reconfigure()
        result = client.dnsmasq.get_host(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "dnsmasq_host": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "dnsmasq_host": existing}

    if check_mode:
        return {"changed": True, "dnsmasq_host": existing}

    obj = _build_obj(params)
    client.dnsmasq.set_host(existing_uuid, obj)
    if params.get("reconfigure"):
        client.dnsmasq.reconfigure()
    result = client.dnsmasq.get_host(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "dnsmasq_host": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        host=dict(type="str", required=False, default=None),
        domain=dict(type="str", required=False, default=None),
        local=dict(type="str", required=False, default=None),
        ip=dict(type="str", required=False, default=None),
        cnames=dict(type="str", required=False, default=None),
        client_id=dict(type="str", required=False, default=None),
        hwaddr=dict(type="str", required=False, default=None),
        lease_time=dict(type="int", required=False, default=None),
        ignore=dict(type="str", required=False, default=None),
        descr=dict(type="str", required=False, default=None),
        comments=dict(type="str", required=False, default=None),
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
