"""Unit tests for the opnsense_firewall_dnat_rule module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_firewall_dnat_rule import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "descr": "Forward HTTP to webserver",
    "disabled": "0",
    "interface": "wan",
    "protocol": "tcp",
    "target": "192.168.1.80",
    "local_port": "80",
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


def test_create_new_dnat_rule(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/d_nat/search_rule").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/firewall/d_nat/add_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/d_nat/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "descr": "Forward HTTP to webserver",
        "enabled": True,
        "sequence": None,
        "nordr": None,
        "interface": "wan",
        "ipprotocol": None,
        "protocol": "tcp",
        "target": "192.168.1.80",
        "local_port": "80",
        "log": None,
        "natreflection": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["dnat_rule"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/d_nat/search_rule").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "descr": "Forward HTTP to webserver",
        "enabled": True,  # disabled="0" means enabled=True
        "sequence": None,
        "nordr": None,
        "interface": "wan",
        "ipprotocol": None,
        "protocol": "tcp",
        "target": "192.168.1.80",
        "local_port": "80",
        "log": None,
        "natreflection": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["dnat_rule"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/d_nat/search_rule").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/firewall/d_nat/set_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "target": "192.168.1.81"}
    mock_api.get(f"/firewall/d_nat/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "descr": "Forward HTTP to webserver",
        "enabled": True,
        "sequence": None,
        "nordr": None,
        "interface": "wan",
        "ipprotocol": None,
        "protocol": "tcp",
        "target": "192.168.1.81",
        "local_port": "80",
        "log": None,
        "natreflection": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/d_nat/search_rule").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/firewall/d_nat/del_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "descr": "Forward HTTP to webserver",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
