"""Unit tests for the opnsense_firewall_snat_rule module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_firewall_snat_rule import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "description": "Outbound NAT for LAN",
    "enabled": "1",
    "interface": "wan",
    "source_net": "192.168.1.0/24",
    "target": "interface",
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


def test_create_new_snat_rule(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/source_nat/search_rule").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/firewall/source_nat/add_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/source_nat/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Outbound NAT for LAN",
        "enabled": True,
        "nonat": None,
        "sequence": None,
        "interface": "wan",
        "ipprotocol": None,
        "protocol": None,
        "source_net": "192.168.1.0/24",
        "source_not": None,
        "source_port": None,
        "destination_net": None,
        "destination_not": None,
        "destination_port": None,
        "target": "interface",
        "target_port": None,
        "staticnatport": None,
        "log": None,
        "categories": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["snat_rule"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/source_nat/search_rule").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Outbound NAT for LAN",
        "enabled": True,
        "nonat": None,
        "sequence": None,
        "interface": "wan",
        "ipprotocol": None,
        "protocol": None,
        "source_net": "192.168.1.0/24",
        "source_not": None,
        "source_port": None,
        "destination_net": None,
        "destination_not": None,
        "destination_port": None,
        "target": "interface",
        "target_port": None,
        "staticnatport": None,
        "log": None,
        "categories": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["snat_rule"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/source_nat/search_rule").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/firewall/source_nat/set_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "source_net": "192.168.2.0/24"}
    mock_api.get(f"/firewall/source_nat/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Outbound NAT for LAN",
        "enabled": True,
        "nonat": None,
        "sequence": None,
        "interface": "wan",
        "ipprotocol": None,
        "protocol": None,
        "source_net": "192.168.2.0/24",
        "source_not": None,
        "source_port": None,
        "destination_net": None,
        "destination_not": None,
        "destination_port": None,
        "target": "interface",
        "target_port": None,
        "staticnatport": None,
        "log": None,
        "categories": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/source_nat/search_rule").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/firewall/source_nat/del_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "description": "Outbound NAT for LAN",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
