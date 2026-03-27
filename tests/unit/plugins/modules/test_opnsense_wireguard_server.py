"""Unit tests for the opnsense_wireguard_server module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_wireguard_server import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "name": "wg0",
    "port": "51820",
    "tunneladdress": "10.10.0.1/24",
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


def test_create_new_server(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/wireguard/server/search_server").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/wireguard/server/add_server").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/wireguard/server/get_server/{_UUID}").mock(
        return_value=Response(200, json={"server": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "wg0",
        "enabled": True,
        "pubkey": None,
        "privkey": None,
        "server_port": "51820",
        "mtu": None,
        "dns": None,
        "tunneladdress": "10.10.0.1/24",
        "disableroutes": None,
        "gateway": None,
        "peers": None,
        "debug": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["wireguard_server"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/wireguard/server/search_server").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "wg0",
        "enabled": True,
        "pubkey": None,
        "privkey": None,
        "server_port": "51820",
        "mtu": None,
        "dns": None,
        "tunneladdress": "10.10.0.1/24",
        "disableroutes": None,
        "gateway": None,
        "peers": None,
        "debug": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["wireguard_server"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/wireguard/server/search_server").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/wireguard/server/set_server/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "tunneladdress": "10.10.1.1/24"}
    mock_api.get(f"/wireguard/server/get_server/{_UUID}").mock(
        return_value=Response(200, json={"server": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "wg0",
        "enabled": True,
        "pubkey": None,
        "privkey": None,
        "server_port": "51820",
        "mtu": None,
        "dns": None,
        "tunneladdress": "10.10.1.1/24",
        "disableroutes": None,
        "gateway": None,
        "peers": None,
        "debug": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/wireguard/server/search_server").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/wireguard/server/del_server/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "name": "wg0",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
