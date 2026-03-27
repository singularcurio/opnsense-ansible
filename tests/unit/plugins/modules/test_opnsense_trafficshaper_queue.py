"""Unit tests for the opnsense_trafficshaper_queue module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_trafficshaper_queue import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"
_PIPE_UUID = "a1b2c3d4-0000-0000-0000-000000000002"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "description": "Bulk Traffic",
    "pipe": _PIPE_UUID,
    "weight": 10,
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


def test_create_new_queue(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_queues").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/trafficshaper/settings/add_queue").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/trafficshaper/settings/get_queue/{_UUID}").mock(
        return_value=Response(200, json={"queue": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Bulk Traffic",
        "enabled": True,
        "pipe": _PIPE_UUID,
        "weight": 10,
        "mask": None,
        "buckets": None,
        "codel_enable": None,
        "codel_target": None,
        "codel_interval": None,
        "codel_ecn_enable": None,
        "pie_enable": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["trafficshaper_queue"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_queues").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Bulk Traffic",
        "enabled": True,
        "pipe": _PIPE_UUID,
        "weight": 10,
        "mask": None,
        "buckets": None,
        "codel_enable": None,
        "codel_target": None,
        "codel_interval": None,
        "codel_ecn_enable": None,
        "pie_enable": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["trafficshaper_queue"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_queues").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/trafficshaper/settings/set_queue/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "weight": 20}
    mock_api.get(f"/trafficshaper/settings/get_queue/{_UUID}").mock(
        return_value=Response(200, json={"queue": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Bulk Traffic",
        "enabled": True,
        "pipe": _PIPE_UUID,
        "weight": 20,
        "mask": None,
        "buckets": None,
        "codel_enable": None,
        "codel_target": None,
        "codel_interval": None,
        "codel_ecn_enable": None,
        "pie_enable": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/trafficshaper/settings/search_queues").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/trafficshaper/settings/del_queue/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "description": "Bulk Traffic",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
