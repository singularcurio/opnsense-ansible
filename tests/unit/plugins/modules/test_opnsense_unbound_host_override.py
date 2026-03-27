"""Unit tests for the opnsense_unbound_host_override module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_unbound_host_override import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "hostname": "myserver",
    "domain": "example.com",
    "rr": "A",
    "server": "192.168.1.100",
    "description": "My server",
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


def test_create_new_host_override(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_host_override").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/unbound/settings/add_host_override").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/unbound/settings/get_host_override/{_UUID}").mock(
        return_value=Response(200, json={"host": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "hostname": "myserver",
        "domain": "example.com",
        "rr": "A",
        "server": "192.168.1.100",
        "mxprio": None,
        "mx": None,
        "ttl": None,
        "txtdata": None,
        "addptr": None,
        "description": "My server",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["host_override"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_host_override").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "hostname": "myserver",
        "domain": "example.com",
        "rr": "A",
        "server": "192.168.1.100",
        "mxprio": None,
        "mx": None,
        "ttl": None,
        "txtdata": None,
        "addptr": None,
        "description": "My server",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["host_override"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_host_override").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/unbound/settings/set_host_override/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "server": "192.168.1.200"}
    mock_api.get(f"/unbound/settings/get_host_override/{_UUID}").mock(
        return_value=Response(200, json={"host": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "hostname": "myserver",
        "domain": "example.com",
        "rr": "A",
        "server": "192.168.1.200",
        "mxprio": None,
        "mx": None,
        "ttl": None,
        "txtdata": None,
        "addptr": None,
        "description": "My server",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_host_override").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/unbound/settings/del_host_override/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "hostname": "myserver",
        "domain": "example.com",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
