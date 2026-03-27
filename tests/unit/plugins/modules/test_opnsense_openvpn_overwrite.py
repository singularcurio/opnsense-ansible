"""Unit tests for the opnsense_openvpn_overwrite module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_openvpn_overwrite import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "servers": "",
    "common_name": "user@example.com",
    "block": "0",
    "push_reset": "0",
    "tunnel_network": "10.8.0.5/24",
    "tunnel_networkv6": "",
    "local_networks": "",
    "remote_networks": "",
    "route_gateway": "",
    "redirect_gateway": "",
    "register_dns": "0",
    "dns_domain": "",
    "dns_servers": "",
    "ntp_servers": "",
    "wins_servers": "",
    "description": "",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "common_name": "user@example.com",
    "enabled": True,
    "servers": None,
    "block": None,
    "push_reset": None,
    "tunnel_network": "10.8.0.5/24",
    "tunnel_networkv6": None,
    "local_networks": None,
    "remote_networks": None,
    "route_gateway": None,
    "redirect_gateway": None,
    "register_dns": None,
    "dns_domain": None,
    "dns_servers": None,
    "ntp_servers": None,
    "wins_servers": None,
    "description": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_overwrite(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/client_overwrites/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/openvpn/client_overwrites/add").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/openvpn/client_overwrites/get/{_UUID}").mock(
        return_value=Response(200, json={"Overwrite": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["openvpn_overwrite"]["uuid"] == _UUID
    assert result["openvpn_overwrite"]["common_name"] == "user@example.com"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/client_overwrites/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["openvpn_overwrite"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/client_overwrites/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["openvpn_overwrite"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/client_overwrites/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/openvpn/client_overwrites/set/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "tunnel_network": "10.8.0.10/24"}
    mock_api.get(f"/openvpn/client_overwrites/get/{_UUID}").mock(
        return_value=Response(200, json={"Overwrite": updated})
    )

    params = {**_BASE_PARAMS, "tunnel_network": "10.8.0.10/24"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["openvpn_overwrite"]["tunnel_network"] == "10.8.0.10/24"


def test_delete_existing_overwrite(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/client_overwrites/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/openvpn/client_overwrites/del/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "common_name": "user@example.com", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/client_overwrites/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "common_name": "user@example.com", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/openvpn/client_overwrites/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/openvpn/client_overwrites/add").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/openvpn/client_overwrites/get/{_UUID}").mock(
        return_value=Response(200, json={"Overwrite": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/openvpn/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
