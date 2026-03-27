"""Unit tests for the opnsense_unbound_host_alias module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_unbound_host_alias import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"
_PARENT_UUID = "a1b2c3d4-0000-0000-0000-000000000002"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "host": _PARENT_UUID,
    "hostname": "alias",
    "domain": "example.com",
    "description": "Alias for main host",
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


def test_create_new_host_alias(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_host_alias").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/unbound/settings/add_host_alias").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/unbound/settings/get_host_alias/{_UUID}").mock(
        return_value=Response(200, json={"host_alias": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "parent_host": _PARENT_UUID,
        "hostname": "alias",
        "domain": "example.com",
        "description": "Alias for main host",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["host_alias"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_host_alias").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "parent_host": _PARENT_UUID,
        "hostname": "alias",
        "domain": "example.com",
        "description": "Alias for main host",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["host_alias"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_host_alias").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/unbound/settings/set_host_alias/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "description": "Updated alias"}
    mock_api.get(f"/unbound/settings/get_host_alias/{_UUID}").mock(
        return_value=Response(200, json={"host_alias": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "parent_host": _PARENT_UUID,
        "hostname": "alias",
        "domain": "example.com",
        "description": "Updated alias",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_host_alias").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/unbound/settings/del_host_alias/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "hostname": "alias",
        "domain": "example.com",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
