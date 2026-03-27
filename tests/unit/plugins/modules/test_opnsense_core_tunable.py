"""Unit tests for the opnsense_core_tunable module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_core_tunable import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_FIELDS = {
    "tunable": "net.inet.ip.forwarding",
    "value": "1",
    "descr": "IP forwarding",
    "enabled": "1",
}
_ITEM_RESPONSE = {"uuid": _UUID, **_ITEM_FIELDS}

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


def test_create_new_tunable(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/core/tunables/search_item").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/core/tunables/add_item").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/core/tunables/get_item/{_UUID}").mock(
        return_value=Response(200, json={"tunable": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "tunable": "net.inet.ip.forwarding",
        "value": "1",
        "descr": "IP forwarding",
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["core_tunable"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/core/tunables/search_item").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "tunable": "net.inet.ip.forwarding",
        "value": "1",
        "descr": "IP forwarding",
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["core_tunable"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/core/tunables/search_item").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/core/tunables/set_item/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "value": "0"}
    mock_api.get(f"/core/tunables/get_item/{_UUID}").mock(
        return_value=Response(200, json={"tunable": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "tunable": "net.inet.ip.forwarding",
        "value": "0",
        "descr": "IP forwarding",
        "enabled": True,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/core/tunables/search_item").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/core/tunables/del_item/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "tunable": "net.inet.ip.forwarding",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
