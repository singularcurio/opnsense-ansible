#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: opnsense_cron_job
short_description: Manage OPNsense cron jobs
version_added: "0.1.0"
description:
  - Create, update, and delete cron jobs on an OPNsense firewall via the REST API.
  - Changes are staged until C(opnsense.core.opnsense_cron_reconfigure) is called,
    or set I(reconfigure=true) to apply immediately.
  - Idempotent: the module compares desired fields against the current state and
    only mutates when something differs.
options:
  state:
    description: Desired state of the cron job.
    type: str
    choices: [present, absent]
    default: present
  uuid:
    description:
      - UUID of an existing cron job.
      - When provided for I(state=present), the module fetches and updates that job.
      - When provided for I(state=absent), the module deletes that job.
      - When omitted, the module searches by I(command) to locate an existing job.
    type: str
    required: false
  command:
    description:
      - Command to execute (required for I(state=present) when I(uuid) is not given).
      - Used as the search key to find existing jobs when I(uuid) is omitted.
    type: str
    required: false
  minutes:
    description: Cron minutes field.
    type: str
    default: "*"
  hours:
    description: Cron hours field.
    type: str
    default: "*"
  days:
    description: Cron day-of-month field.
    type: str
    default: "*"
  months:
    description: Cron months field.
    type: str
    default: "*"
  weekdays:
    description: Cron day-of-week field.
    type: str
    default: "*"
  who:
    description: User to run the command as.
    type: str
    default: "root"
  parameters:
    description: Optional parameters passed to the command.
    type: str
    required: false
  description:
    description: Human-readable label for this job.
    type: str
    required: false
  enabled:
    description: Whether the job is active.
    type: bool
    default: true
  reconfigure:
    description: Apply pending cron changes immediately after mutating the job.
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
- name: Create a daily firmware-check cron job
  opnsense.core.opnsense_cron_job:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    verify_ssl: false
    command: /usr/local/sbin/firmware-check
    minutes: "0"
    hours: "2"
    description: Daily firmware check
    state: present
    reconfigure: true

- name: Remove a cron job identified by UUID
  opnsense.core.opnsense_cron_job:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    state: absent
    reconfigure: true

- name: Disable a cron job
  opnsense.core.opnsense_cron_job:
    host: "{{ opnsense_host }}"
    api_key: "{{ opnsense_api_key }}"
    api_secret: "{{ opnsense_api_secret }}"
    command: /usr/local/sbin/firmware-check
    enabled: false
    state: present
"""

RETURN = r"""
cron_job:
  description: The cron job object after the operation.
  type: dict
  returned: when state is present
  sample:
    uuid: "a1b2c3d4-0000-0000-0000-000000000001"
    command: /usr/local/sbin/firmware-check
    minutes: "0"
    hours: "2"
    days: "*"
    months: "*"
    weekdays: "*"
    who: root
    enabled: "1"
    description: Daily firmware check
"""

try:
    from ansible.module_utils.basic import AnsibleModule
    from ansible_collections.opnsense.core.plugins.module_utils.opnsense import (
        build_client,
        client_argument_spec,
    )
except ImportError:
    # Allows direct import during unit testing when the collection is not installed.
    from ansible.module_utils.basic import AnsibleModule  # type: ignore[no-redef]
    from module_utils.opnsense import build_client, client_argument_spec  # type: ignore[no-redef]

from opnsense_py.client import OPNsenseClient
from opnsense_py.exceptions import OPNsenseError, OPNsenseNotFoundError
from opnsense_py.models.base import SearchRequest
from opnsense_py.models.cron import CronJob

# Fields that form the diff comparison between desired and existing state.
_CRON_FIELDS = ("command", "minutes", "hours", "days", "months", "weekdays", "who",
                "parameters", "description")


def _bool_to_api(value: bool) -> str:
    return "1" if value else "0"


def _find_by_uuid(client: OPNsenseClient, uuid: str) -> tuple[str, dict] | tuple[None, None]:
    """Return (uuid, job_dict) for a known UUID, or (None, None) if not found."""
    try:
        job = client.cron.get_job(uuid)
        return uuid, job.model_dump(exclude_none=True)
    except OPNsenseNotFoundError:
        return None, None


def _find_by_command(
    client: OPNsenseClient, command: str
) -> tuple[str, dict] | tuple[None, None]:
    """Search for the first cron job whose command matches exactly.

    Returns (uuid, job_dict) or (None, None) if nothing matches.
    When multiple jobs share the same command, the first result is used.
    """
    result = client.cron.search_jobs(SearchRequest(searchPhrase=command))
    for job in result.rows:
        row = job.model_dump()
        if row.get("command") == command:
            uuid = row.get("uuid")
            if uuid:
                return uuid, {k: v for k, v in row.items() if v is not None}
    return None, None


def _needs_update(existing: dict, params: dict) -> bool:
    """Return True if any desired cron field differs from the existing job."""
    for field in _CRON_FIELDS:
        desired = params.get(field)
        if desired is None:
            continue
        if existing.get(field) != desired:
            return True
    # Check enabled separately (bool -> "0"/"1" conversion)
    desired_enabled = params.get("enabled")
    if desired_enabled is not None:
        if existing.get("enabled") != _bool_to_api(desired_enabled):
            return True
    return False


def _build_cron_job(params: dict) -> CronJob:
    enabled = params.get("enabled")
    return CronJob(
        command=params.get("command"),
        minutes=params.get("minutes"),
        hours=params.get("hours"),
        days=params.get("days"),
        months=params.get("months"),
        weekdays=params.get("weekdays"),
        who=params.get("who"),
        parameters=params.get("parameters"),
        description=params.get("description"),
        enabled=_bool_to_api(enabled) if enabled is not None else None,
    )


def run(params: dict, check_mode: bool, client: OPNsenseClient) -> dict:
    """Core module logic. Returns the dict passed to ``exit_json``.

    Separated from ``run_module()`` so tests can call it directly without
    instantiating ``AnsibleModule``.
    """
    state = params.get("state", "present")
    uuid = params.get("uuid")
    command = params.get("command")

    # ------------------------------------------------------------------ #
    # Locate existing job                                                  #
    # ------------------------------------------------------------------ #
    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif command:
        existing_uuid, existing = _find_by_command(client, command)
    else:
        existing_uuid, existing = None, None

    # ------------------------------------------------------------------ #
    # state: absent                                                        #
    # ------------------------------------------------------------------ #
    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.cron.del_job(existing_uuid)
            if params.get("reconfigure"):
                client.cron.reconfigure()
        return {"changed": True}

    # ------------------------------------------------------------------ #
    # state: present — validate required fields                            #
    # ------------------------------------------------------------------ #
    if not command:
        raise OPNsenseError("'command' is required when state is 'present'")

    # ------------------------------------------------------------------ #
    # state: present — create                                              #
    # ------------------------------------------------------------------ #
    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "cron_job": None}
        job_obj = _build_cron_job(params)
        response = client.cron.add_job(job_obj)
        new_uuid = response.uuid
        if params.get("reconfigure"):
            client.cron.reconfigure()
        result_job = client.cron.get_job(new_uuid).model_dump(exclude_none=True)
        result_job["uuid"] = new_uuid
        return {"changed": True, "cron_job": result_job}

    # ------------------------------------------------------------------ #
    # state: present — update if needed                                    #
    # ------------------------------------------------------------------ #
    if not _needs_update(existing, params):
        existing["uuid"] = existing_uuid
        return {"changed": False, "cron_job": existing}

    if check_mode:
        return {"changed": True, "cron_job": existing}

    job_obj = _build_cron_job(params)
    client.cron.set_job(existing_uuid, job_obj)
    if params.get("reconfigure"):
        client.cron.reconfigure()
    result_job = client.cron.get_job(existing_uuid).model_dump(exclude_none=True)
    result_job["uuid"] = existing_uuid
    return {"changed": True, "cron_job": result_job}


def run_module() -> None:
    argument_spec = dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        uuid=dict(type="str", required=False, default=None),
        command=dict(type="str", required=False, default=None),
        minutes=dict(type="str", default="*"),
        hours=dict(type="str", default="*"),
        days=dict(type="str", default="*"),
        months=dict(type="str", default="*"),
        weekdays=dict(type="str", default="*"),
        who=dict(type="str", default="root"),
        parameters=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
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
