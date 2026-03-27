"""Unit tests for the opnsense_openvpn_instance module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_openvpn_instance import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "dev_type": "tun",
    "proto": "udp",
    "port": "1194",
    "role": "server",
    "description": "Main VPN server",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "description": "Main VPN server",
    "enabled": True,
    "dev_type": "tun",
    "proto": "udp",
    "port": "1194",
    "local": None,
    "topology": None,
    "remote": None,
    "role": "server",
    "server": None,
    "server_ipv6": None,
    "cert": None,
    "ca": None,
    "crl": None,
    "cert_depth": None,
    "remote_cert_tls": None,
    "verify_client_cert": None,
    "auth": None,
    "tls_key": None,
    "authmode": None,
    "local_group": None,
    "maxclients": None,
    "keepalive_interval": None,
    "keepalive_timeout": None,
    "reneg_sec": None,
    "register_dns": None,
    "dns_domain": None,
    "dns_servers": None,
    "tun_mtu": None,
    "carp_depend_on": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_instance(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/instances/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/openvpn/instances/add").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/openvpn/instances/get/{_UUID}").mock(
        return_value=Response(200, json={"instance": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["openvpn_instance"]["uuid"] == _UUID
    assert result["openvpn_instance"]["description"] == "Main VPN server"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/instances/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["openvpn_instance"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/instances/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["openvpn_instance"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/instances/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/openvpn/instances/set/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "port": "1195"}
    mock_api.get(f"/openvpn/instances/get/{_UUID}").mock(
        return_value=Response(200, json={"instance": updated})
    )

    params = {**_BASE_PARAMS, "port": "1195"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["openvpn_instance"]["port"] == "1195"


def test_delete_existing_instance(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/instances/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/openvpn/instances/del/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "description": "Main VPN server", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/openvpn/instances/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "description": "Main VPN server", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/openvpn/instances/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/openvpn/instances/add").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/openvpn/instances/get/{_UUID}").mock(
        return_value=Response(200, json={"instance": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/openvpn/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
