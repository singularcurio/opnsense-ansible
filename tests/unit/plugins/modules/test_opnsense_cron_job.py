"""Unit tests for the opnsense_cron_job module.

All tests call ``run()`` directly and mock the OPNsense HTTP API via ``respx``,
mirroring the testing approach used in opnsense-py and opnsense-mcp.
"""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient

# Imported via the sys.path manipulation in conftest.py.
from opnsense_cron_job import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"

_JOB_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_JOB_RESPONSE = {
    "uuid": _JOB_UUID,
    "enabled": "1",
    "minutes": "0",
    "hours": "2",
    "days": "*",
    "months": "*",
    "weekdays": "*",
    "who": "root",
    "command": "/usr/local/sbin/firmware-check",
    "parameters": None,
    "description": "Daily firmware check",
    "origin": None,
}

_SEARCH_HIT = {
    "total": 1,
    "rowCount": 500,
    "current": 1,
    "rows": [_JOB_RESPONSE],
}

_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


# --------------------------------------------------------------------------- #
# state: present — create                                                      #
# --------------------------------------------------------------------------- #


def test_create_new_job(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/cron/settings/search_jobs").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/cron/settings/add_job").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _JOB_UUID})
    )
    mock_api.get(f"/cron/settings/get_job/{_JOB_UUID}").mock(
        return_value=Response(200, json={"job": _JOB_RESPONSE})
    )

    params = {
        "state": "present",
        "uuid": None,
        "command": "/usr/local/sbin/firmware-check",
        "minutes": "0",
        "hours": "2",
        "days": "*",
        "months": "*",
        "weekdays": "*",
        "who": "root",
        "parameters": None,
        "description": "Daily firmware check",
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["cron_job"]["uuid"] == _JOB_UUID
    assert result["cron_job"]["command"] == "/usr/local/sbin/firmware-check"


def test_create_check_mode_no_api_call(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/cron/settings/search_jobs").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {
        "state": "present",
        "uuid": None,
        "command": "/usr/local/sbin/firmware-check",
        "minutes": "0",
        "hours": "2",
        "days": "*",
        "months": "*",
        "weekdays": "*",
        "who": "root",
        "parameters": None,
        "description": None,
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["cron_job"] is None


# --------------------------------------------------------------------------- #
# state: present — update                                                      #
# --------------------------------------------------------------------------- #


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/cron/settings/search_jobs").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/cron/settings/set_job/{_JOB_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_JOB_RESPONSE, "hours": "4"}
    mock_api.get(f"/cron/settings/get_job/{_JOB_UUID}").mock(
        return_value=Response(200, json={"job": updated})
    )

    params = {
        "state": "present",
        "uuid": None,
        "command": "/usr/local/sbin/firmware-check",
        "minutes": "0",
        "hours": "4",  # changed
        "days": "*",
        "months": "*",
        "weekdays": "*",
        "who": "root",
        "parameters": None,
        "description": "Daily firmware check",
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["cron_job"]["hours"] == "4"


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/cron/settings/search_jobs").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    params = {
        "state": "present",
        "uuid": None,
        "command": "/usr/local/sbin/firmware-check",
        "minutes": "0",
        "hours": "2",
        "days": "*",
        "months": "*",
        "weekdays": "*",
        "who": "root",
        "parameters": None,
        "description": "Daily firmware check",
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["cron_job"]["uuid"] == _JOB_UUID


def test_update_by_uuid(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    updated = {**_JOB_RESPONSE, "description": "Updated description"}
    # Two successive GET calls return different responses.
    get_responses = iter([
        Response(200, json={"job": _JOB_RESPONSE}),
        Response(200, json={"job": updated}),
    ])
    mock_api.get(f"/cron/settings/get_job/{_JOB_UUID}").mock(
        side_effect=lambda _req: next(get_responses)
    )
    mock_api.post(f"/cron/settings/set_job/{_JOB_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )

    params = {
        "state": "present",
        "uuid": _JOB_UUID,
        "command": "/usr/local/sbin/firmware-check",
        "minutes": "0",
        "hours": "2",
        "days": "*",
        "months": "*",
        "weekdays": "*",
        "who": "root",
        "parameters": None,
        "description": "Updated description",
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["cron_job"]["description"] == "Updated description"


# --------------------------------------------------------------------------- #
# state: absent                                                                #
# --------------------------------------------------------------------------- #


def test_delete_existing_job(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/cron/settings/search_jobs").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/cron/settings/del_job/{_JOB_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        "state": "absent",
        "uuid": None,
        "command": "/usr/local/sbin/firmware-check",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert "cron_job" not in result


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/cron/settings/search_jobs").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {
        "state": "absent",
        "uuid": None,
        "command": "/usr/local/sbin/firmware-check",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_absent_check_mode_no_delete(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/cron/settings/search_jobs").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    params = {
        "state": "absent",
        "uuid": None,
        "command": "/usr/local/sbin/firmware-check",
        "reconfigure": False,
    }
    result = run(params, check_mode=True, client=client)

    assert result["changed"] is True


def test_absent_by_uuid(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.get(f"/cron/settings/get_job/{_JOB_UUID}").mock(
        return_value=Response(200, json={"job": _JOB_RESPONSE})
    )
    mock_api.post(f"/cron/settings/del_job/{_JOB_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        "state": "absent",
        "uuid": _JOB_UUID,
        "command": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


# --------------------------------------------------------------------------- #
# reconfigure                                                                  #
# --------------------------------------------------------------------------- #


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/cron/settings/search_jobs").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/cron/settings/add_job").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _JOB_UUID})
    )
    mock_api.get(f"/cron/settings/get_job/{_JOB_UUID}").mock(
        return_value=Response(200, json={"job": _JOB_RESPONSE})
    )
    reconfigure_route = mock_api.post("/cron/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {
        "state": "present",
        "uuid": None,
        "command": "/usr/local/sbin/firmware-check",
        "minutes": "0",
        "hours": "2",
        "days": "*",
        "months": "*",
        "weekdays": "*",
        "who": "root",
        "parameters": None,
        "description": None,
        "enabled": True,
        "reconfigure": True,
    }
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
