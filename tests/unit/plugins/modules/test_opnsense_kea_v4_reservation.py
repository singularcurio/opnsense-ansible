"""Unit tests for the opnsense_kea_v4_reservation module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_kea_v4_reservation import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "ip_address": "192.168.1.50",
    "hw_address": "aa:bb:cc:dd:ee:ff",
    "hostname": "myserver",
    "description": "Reserved for myserver",
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


def test_create_new_reservation(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_reservation").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/kea/dhcpv4/add_reservation").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/kea/dhcpv4/get_reservation/{_UUID}").mock(
        return_value=Response(200, json={"reservation": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "ip_address": "192.168.1.50",
        "subnet": None,
        "hw_address": "aa:bb:cc:dd:ee:ff",
        "hostname": "myserver",
        "description": "Reserved for myserver",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["kea_v4_reservation"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_reservation").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "ip_address": "192.168.1.50",
        "subnet": None,
        "hw_address": "aa:bb:cc:dd:ee:ff",
        "hostname": "myserver",
        "description": "Reserved for myserver",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["kea_v4_reservation"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_reservation").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/kea/dhcpv4/set_reservation/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "hostname": "newserver"}
    mock_api.get(f"/kea/dhcpv4/get_reservation/{_UUID}").mock(
        return_value=Response(200, json={"reservation": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "ip_address": "192.168.1.50",
        "subnet": None,
        "hw_address": "aa:bb:cc:dd:ee:ff",
        "hostname": "newserver",
        "description": "Reserved for myserver",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_reservation").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/kea/dhcpv4/del_reservation/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "ip_address": "192.168.1.50",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
