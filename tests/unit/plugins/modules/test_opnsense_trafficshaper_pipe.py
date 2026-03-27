"""Unit tests for the opnsense_trafficshaper_pipe module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_trafficshaper_pipe import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "description": "WAN Download",
    "bandwidth": 100,
    "bandwidthMetric": "Mbit",
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


def test_create_new_pipe(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_pipes").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/trafficshaper/settings/add_pipe").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/trafficshaper/settings/get_pipe/{_UUID}").mock(
        return_value=Response(200, json={"pipe": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "WAN Download",
        "enabled": True,
        "bandwidth": 100,
        "bandwidthMetric": "Mbit",
        "queue": None,
        "mask": None,
        "buckets": None,
        "scheduler": None,
        "codel_enable": None,
        "codel_target": None,
        "codel_interval": None,
        "codel_ecn_enable": None,
        "pie_enable": None,
        "delay": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["trafficshaper_pipe"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_pipes").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "WAN Download",
        "enabled": True,
        "bandwidth": 100,
        "bandwidthMetric": "Mbit",
        "queue": None,
        "mask": None,
        "buckets": None,
        "scheduler": None,
        "codel_enable": None,
        "codel_target": None,
        "codel_interval": None,
        "codel_ecn_enable": None,
        "pie_enable": None,
        "delay": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["trafficshaper_pipe"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_pipes").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/trafficshaper/settings/set_pipe/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "bandwidth": 200}
    mock_api.get(f"/trafficshaper/settings/get_pipe/{_UUID}").mock(
        return_value=Response(200, json={"pipe": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "WAN Download",
        "enabled": True,
        "bandwidth": 200,
        "bandwidthMetric": "Mbit",
        "queue": None,
        "mask": None,
        "buckets": None,
        "scheduler": None,
        "codel_enable": None,
        "codel_target": None,
        "codel_interval": None,
        "codel_ecn_enable": None,
        "pie_enable": None,
        "delay": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_pipes").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/trafficshaper/settings/del_pipe/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "description": "WAN Download",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
