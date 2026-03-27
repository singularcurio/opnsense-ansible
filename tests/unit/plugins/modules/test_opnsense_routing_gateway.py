"""Unit tests for the opnsense_routing_gateway module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_routing_gateway import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "name": "WAN_GW",
    "interface": "wan",
    "ipprotocol": "inet",
    "gateway": "203.0.113.1",
    "descr": "WAN Gateway",
    "disabled": "0",
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


def test_create_new_gateway(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/routing/settings/search_gateway").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/routing/settings/add_gateway").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/routing/settings/get_gateway/{_UUID}").mock(
        return_value=Response(200, json={"gateway": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "WAN_GW",
        "descr": "WAN Gateway",
        "interface": "wan",
        "ipprotocol": "inet",
        "gateway": "203.0.113.1",
        "defaultgw": None,
        "fargw": None,
        "monitor_disable": None,
        "monitor_noroute": None,
        "monitor": None,
        "force_down": None,
        "priority": None,
        "weight": None,
        "latencylow": None,
        "latencyhigh": None,
        "losslow": None,
        "losshigh": None,
        "interval": None,
        "time_period": None,
        "loss_interval": None,
        "data_length": None,
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["gateway"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/routing/settings/search_gateway").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "WAN_GW",
        "descr": "WAN Gateway",
        "interface": "wan",
        "ipprotocol": "inet",
        "gateway": "203.0.113.1",
        "defaultgw": None,
        "fargw": None,
        "monitor_disable": None,
        "monitor_noroute": None,
        "monitor": None,
        "force_down": None,
        "priority": None,
        "weight": None,
        "latencylow": None,
        "latencyhigh": None,
        "losslow": None,
        "losshigh": None,
        "interval": None,
        "time_period": None,
        "loss_interval": None,
        "data_length": None,
        "enabled": True,  # disabled="0" means enabled=True
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["gateway"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/routing/settings/search_gateway").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/routing/settings/set_gateway/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "descr": "Updated WAN GW"}
    mock_api.get(f"/routing/settings/get_gateway/{_UUID}").mock(
        return_value=Response(200, json={"gateway": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "WAN_GW",
        "descr": "Updated WAN GW",
        "interface": "wan",
        "ipprotocol": "inet",
        "gateway": "203.0.113.1",
        "defaultgw": None,
        "fargw": None,
        "monitor_disable": None,
        "monitor_noroute": None,
        "monitor": None,
        "force_down": None,
        "priority": None,
        "weight": None,
        "latencylow": None,
        "latencyhigh": None,
        "losslow": None,
        "losshigh": None,
        "interval": None,
        "time_period": None,
        "loss_interval": None,
        "data_length": None,
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/routing/settings/search_gateway").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/routing/settings/del_gateway/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "name": "WAN_GW",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
