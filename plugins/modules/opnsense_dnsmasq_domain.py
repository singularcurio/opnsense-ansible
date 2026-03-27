#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_dnsmasq_domain
short_description: Manage Dnsmasq domain overrides
version_added: "0.1.0"
description:
  - Create, update, and delete Dnsmasq domain overrides on an OPNsense firewall.
  - Natural key is the I(domain) field.
  - Set I(reconfigure=true) to apply changes immediately.
options:
  state:
    description: Desired state of the domain override.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description: UUID of an existing domain override.
    type: str
    required: false
  domain:
    description: Domain name to override. Used as natural key.
    type: str
    required: false
  ip:
    description: DNS server IP for this domain.
    type: str
    required: false
  srcip:
    description: Source IP to use for queries to this domain.
    type: str
    required: false
  dns_port:
    description: DNS server port for this domain. Maps to the C(port) field in the API.
    type: str
    required: false
  descr:
    description: Human-readable description.
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
- name: Create a Dnsmasq domain override
  opnsense.core.opnsense_dnsmasq_domain:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    domain: "example.internal"
    ip: "10.0.0.53"
    state: present
    reconfigure: true

- name: Remove a domain override
  opnsense.core.opnsense_dnsmasq_domain:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    domain: "example.internal"
    state: absent
"""

RETURN = r"""
dnsmasq_domain:
  description: The Dnsmasq domain override object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    domain: "example.internal"
    ip: "10.0.0.53"
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
from opnsense_py.models.dnsmasq import DnsmasqDomainOverride

# Note: dns_port in Ansible params maps to port in the model/API.
_FIELDS = ("domain", "ip", "srcip", "descr")
_PORT_FIELD = "dns_port"


def _find_by_uuid(client: OPNsenseClient, uuid: str):
    try:
        obj = client.dnsmasq.get_domain(uuid)
        return uuid, obj.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_domain(client: OPNsenseClient, domain: str):
    result = client.dnsmasq.search_domains(SearchRequest(searchPhrase=domain))
    for item in result.rows:
        row = item.model_dump()
        if row.get("domain") == domain:
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
    # dns_port maps to port in the stored object
    desired_port = params.get(_PORT_FIELD)
    if desired_port is not None:
        if existing.get("port") != desired_port:
            return True
    return False


def _build_obj(params: dict) -> DnsmasqDomainOverride:
    return DnsmasqDomainOverride(
        domain=params.get("domain"),
        ip=params.get("ip"),
        srcip=params.get("srcip"),
        port=params.get("dns_port"),
        descr=params.get("descr"),
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    domain = params.get("domain")

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif domain:
        existing_uuid, existing = _find_by_domain(client, domain)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.dnsmasq.del_domain(existing_uuid)
            if params.get("reconfigure"):
                client.dnsmasq.reconfigure()
        return {"changed": True}

    if not domain:
        raise OPNsenseError("'domain' is required when state is 'present'")

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "dnsmasq_domain": None}
        obj = _build_obj(params)
        response = client.dnsmasq.add_domain(obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.dnsmasq.reconfigure()
        result = client.dnsmasq.get_domain(new_uuid).model_dump(exclude_none=True)
        result["uuid"] = new_uuid
        return {"changed": True, "dnsmasq_domain": result}

    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "dnsmasq_domain": existing}

    if check_mode:
        return {"changed": True, "dnsmasq_domain": existing}

    obj = _build_obj(params)
    client.dnsmasq.set_domain(existing_uuid, obj)
    if params.get("reconfigure"):
        client.dnsmasq.reconfigure()
    result = client.dnsmasq.get_domain(existing_uuid).model_dump(exclude_none=True)
    result["uuid"] = existing_uuid
    return {"changed": True, "dnsmasq_domain": result}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        domain=dict(type="str", required=False, default=None),
        ip=dict(type="str", required=False, default=None),
        srcip=dict(type="str", required=False, default=None),
        dns_port=dict(type="str", required=False, default=None),
        descr=dict(type="str", required=False, default=None),
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
