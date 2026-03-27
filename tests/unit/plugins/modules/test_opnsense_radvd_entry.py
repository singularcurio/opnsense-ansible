"""Unit tests for the opnsense_radvd_entry module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_radvd_entry import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "interface": "lan",
    "ra_flags": None,
    "ra_prio": None,
    "ra_interval": None,
    "ra_lifetime": None,
    "mtu": None,
    "description": "LAN radvd",
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


def test_create_new_entry(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/radvd/settings/search_entry").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/radvd/settings/add_entry").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/radvd/settings/get_entry/{_UUID}").mock(
        return_value=Response(200, json={"entry": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "interface": "lan",
        "enabled": True,
        "ra_flags": None,
        "ra_prio": None,
        "ra_interval": None,
        "ra_lifetime": None,
        "mtu": None,
        "description": "LAN radvd",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["radvd_entry"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/radvd/settings/search_entry").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "interface": "lan",
        "enabled": True,
        "ra_flags": None,
        "ra_prio": None,
        "ra_interval": None,
        "ra_lifetime": None,
        "mtu": None,
        "description": "LAN radvd",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["radvd_entry"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/radvd/settings/search_entry").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/radvd/settings/set_entry/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "description": "Updated radvd"}
    mock_api.get(f"/radvd/settings/get_entry/{_UUID}").mock(
        return_value=Response(200, json={"entry": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "interface": "lan",
        "enabled": True,
        "ra_flags": None,
        "ra_prio": None,
        "ra_interval": None,
        "ra_lifetime": None,
        "mtu": None,
        "description": "Updated radvd",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/radvd/settings/search_entry").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/radvd/settings/del_entry/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "interface": "lan",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
