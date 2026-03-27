"""Unit tests for the opnsense_monit_alert module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_monit_alert import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "recipient": "admin@example.com",
    "events": "failure,timeout,stopped",
    "reminder": 10,
    "description": "Admin alerts",
}

_CONN = {
    "host": "opnsense.test",
    "api_key": "key",
    "api_secret": "secret",
    "verify_ssl": True,
    "port": None,
    "https": True,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_alert(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_alert").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/monit/settings/add_alert").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/monit/settings/get_alert/{_UUID}").mock(
        return_value=Response(200, json={"alert": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "recipient": "admin@example.com",
        "enabled": True,
        "noton": None,
        "events": "failure,timeout,stopped",
        "format": None,
        "reminder": 10,
        "description": "Admin alerts",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["monit_alert"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_alert").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "recipient": "admin@example.com",
        "enabled": True,
        "noton": None,
        "events": "failure,timeout,stopped",
        "format": None,
        "reminder": 10,
        "description": "Admin alerts",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["monit_alert"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_alert").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/monit/settings/set_alert/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "reminder": 20}
    mock_api.get(f"/monit/settings/get_alert/{_UUID}").mock(
        return_value=Response(200, json={"alert": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "recipient": "admin@example.com",
        "enabled": True,
        "noton": None,
        "events": "failure,timeout,stopped",
        "format": None,
        "reminder": 20,
        "description": "Admin alerts",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_alert").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/monit/settings/del_alert/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "recipient": "admin@example.com",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
