"""Unit tests for the opnsense_dnsmasq_host module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_dnsmasq_host import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "host": "myserver",
    "domain": "example.com",
    "ip": "192.168.1.50",
    "descr": "My server",
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


def test_create_new_host(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dnsmasq/settings/search_host").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/dnsmasq/settings/add_host").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/dnsmasq/settings/get_host/{_UUID}").mock(
        return_value=Response(200, json={"host": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "host": "myserver",
        "domain": "example.com",
        "ip": "192.168.1.50",
        "local": None,
        "cnames": None,
        "client_id": None,
        "hwaddr": None,
        "lease_time": None,
        "ignore": None,
        "descr": "My server",
        "comments": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["dnsmasq_host"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dnsmasq/settings/search_host").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "host": "myserver",
        "domain": "example.com",
        "ip": "192.168.1.50",
        "local": None,
        "cnames": None,
        "client_id": None,
        "hwaddr": None,
        "lease_time": None,
        "ignore": None,
        "descr": "My server",
        "comments": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["dnsmasq_host"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dnsmasq/settings/search_host").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/dnsmasq/settings/set_host/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "ip": "192.168.1.51"}
    mock_api.get(f"/dnsmasq/settings/get_host/{_UUID}").mock(
        return_value=Response(200, json={"host": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "host": "myserver",
        "domain": "example.com",
        "ip": "192.168.1.51",
        "local": None,
        "cnames": None,
        "client_id": None,
        "hwaddr": None,
        "lease_time": None,
        "ignore": None,
        "descr": "My server",
        "comments": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dnsmasq/settings/search_host").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/dnsmasq/settings/del_host/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "host": "myserver",
        "domain": "example.com",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
