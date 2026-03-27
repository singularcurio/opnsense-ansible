"""Unit tests for the opnsense_dnsmasq_domain module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_dnsmasq_domain import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "domain": "example.internal",
    "ip": "10.0.0.53",
    "port": "53",
    "srcip": None,
    "descr": "Internal domain",
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


def test_create_new_domain(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dnsmasq/settings/search_domain").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/dnsmasq/settings/add_domain").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/dnsmasq/settings/get_domain/{_UUID}").mock(
        return_value=Response(200, json={"domainoverride": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "domain": "example.internal",
        "ip": "10.0.0.53",
        "srcip": None,
        "dns_port": "53",
        "descr": "Internal domain",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["dnsmasq_domain"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dnsmasq/settings/search_domain").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "domain": "example.internal",
        "ip": "10.0.0.53",
        "srcip": None,
        "dns_port": "53",
        "descr": "Internal domain",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["dnsmasq_domain"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dnsmasq/settings/search_domain").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/dnsmasq/settings/set_domain/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "ip": "10.0.0.54"}
    mock_api.get(f"/dnsmasq/settings/get_domain/{_UUID}").mock(
        return_value=Response(200, json={"domainoverride": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "domain": "example.internal",
        "ip": "10.0.0.54",
        "srcip": None,
        "dns_port": "53",
        "descr": "Internal domain",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dnsmasq/settings/search_domain").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/dnsmasq/settings/del_domain/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "domain": "example.internal",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
