"""Unit tests for the opnsense_trafficshaper_rule module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_trafficshaper_rule import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"
_TARGET_UUID = "a1b2c3d4-0000-0000-0000-000000000002"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "description": "Shape HTTP traffic",
    "interface": "wan",
    "proto": "tcp",
    "dst_port": "80",
    "target": _TARGET_UUID,
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


def test_create_new_rule(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_rules").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/trafficshaper/settings/add_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/trafficshaper/settings/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Shape HTTP traffic",
        "enabled": True,
        "sequence": None,
        "interface": "wan",
        "interface2": None,
        "proto": "tcp",
        "iplen": None,
        "source": None,
        "source_not": None,
        "src_port": None,
        "destination": None,
        "destination_not": None,
        "dst_port": "80",
        "dscp": None,
        "direction": None,
        "target": _TARGET_UUID,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["trafficshaper_rule"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_rules").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Shape HTTP traffic",
        "enabled": True,
        "sequence": None,
        "interface": "wan",
        "interface2": None,
        "proto": "tcp",
        "iplen": None,
        "source": None,
        "source_not": None,
        "src_port": None,
        "destination": None,
        "destination_not": None,
        "dst_port": "80",
        "dscp": None,
        "direction": None,
        "target": _TARGET_UUID,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["trafficshaper_rule"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_rules").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/trafficshaper/settings/set_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "dst_port": "443"}
    mock_api.get(f"/trafficshaper/settings/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Shape HTTP traffic",
        "enabled": True,
        "sequence": None,
        "interface": "wan",
        "interface2": None,
        "proto": "tcp",
        "iplen": None,
        "source": None,
        "source_not": None,
        "src_port": None,
        "destination": None,
        "destination_not": None,
        "dst_port": "443",
        "dscp": None,
        "direction": None,
        "target": _TARGET_UUID,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_rules").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/trafficshaper/settings/del_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "description": "Shape HTTP traffic",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
