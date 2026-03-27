"""Unit tests for the opnsense_firewall_category module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_firewall_category import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "name": "WAN traffic",
    "auto": "0",
    "color": "ff0000",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "name": "WAN traffic",
    "auto": None,
    "color": "ff0000",
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_category(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/category/search_item").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/firewall/category/add_item").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/category/get_item/{_UUID}").mock(
        return_value=Response(200, json={"category": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["firewall_category"]["uuid"] == _UUID
    assert result["firewall_category"]["name"] == "WAN traffic"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/category/search_item").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["firewall_category"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/category/search_item").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["firewall_category"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/category/search_item").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/firewall/category/set_item/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "color": "00ff00"}
    mock_api.get(f"/firewall/category/get_item/{_UUID}").mock(
        return_value=Response(200, json={"category": updated})
    )

    params = {**_BASE_PARAMS, "color": "00ff00"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["firewall_category"]["color"] == "00ff00"


def test_delete_existing_category(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/category/search_item").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/firewall/category/del_item/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "name": "WAN traffic", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/category/search_item").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "name": "WAN traffic", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/firewall/category/search_item").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/firewall/category/add_item").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/category/get_item/{_UUID}").mock(
        return_value=Response(200, json={"category": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/firewall/filter/apply").mock(
        return_value=Response(200, json={"status": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
