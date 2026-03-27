"""Unit tests for the opnsense_kea_v4_subnet module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_kea_v4_subnet import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "subnet": "192.168.1.0/24",
    "pools": "192.168.1.100-192.168.1.200",
    "description": "LAN subnet",
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


def test_create_new_subnet(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_subnet").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/kea/dhcpv4/add_subnet").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/kea/dhcpv4/get_subnet/{_UUID}").mock(
        return_value=Response(200, json={"subnet4": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "subnet": "192.168.1.0/24",
        "next_server": None,
        "option_data_autocollect": None,
        "pools": "192.168.1.100-192.168.1.200",
        "match_client_id": None,
        "ddns_forward_zone": None,
        "ddns_dns_server": None,
        "description": "LAN subnet",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["kea_v4_subnet"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_subnet").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "subnet": "192.168.1.0/24",
        "next_server": None,
        "option_data_autocollect": None,
        "pools": "192.168.1.100-192.168.1.200",
        "match_client_id": None,
        "ddns_forward_zone": None,
        "ddns_dns_server": None,
        "description": "LAN subnet",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["kea_v4_subnet"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_subnet").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/kea/dhcpv4/set_subnet/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "description": "Updated LAN subnet"}
    mock_api.get(f"/kea/dhcpv4/get_subnet/{_UUID}").mock(
        return_value=Response(200, json={"subnet4": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "subnet": "192.168.1.0/24",
        "next_server": None,
        "option_data_autocollect": None,
        "pools": "192.168.1.100-192.168.1.200",
        "match_client_id": None,
        "ddns_forward_zone": None,
        "ddns_dns_server": None,
        "description": "Updated LAN subnet",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_subnet").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/kea/dhcpv4/del_subnet/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "subnet": "192.168.1.0/24",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
