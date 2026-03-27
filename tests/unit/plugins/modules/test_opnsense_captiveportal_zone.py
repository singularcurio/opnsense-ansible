"""Unit tests for the opnsense_captiveportal_zone module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_captiveportal_zone import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "zoneid": "0",
    "interfaces": "lan",
    "authservers": "",
    "idletimeout": "0",
    "hardtimeout": "0",
    "concurrentlogins": "1",
    "bandwidth_up": "0",
    "bandwidth_down": "0",
    "description": "Guest WiFi",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "description": "Guest WiFi",
    "enabled": True,
    "zoneid": None,
    "interfaces": "lan",
    "authservers": None,
    "idletimeout": None,
    "hardtimeout": None,
    "concurrentlogins": None,
    "bandwidth_up": None,
    "bandwidth_down": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_zone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/captiveportal/settings/search_zones").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/captiveportal/settings/add_zone").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/captiveportal/settings/get_zone/{_UUID}").mock(
        return_value=Response(200, json={"zone": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["captiveportal_zone"]["uuid"] == _UUID
    assert result["captiveportal_zone"]["description"] == "Guest WiFi"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/captiveportal/settings/search_zones").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["captiveportal_zone"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/captiveportal/settings/search_zones").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["captiveportal_zone"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/captiveportal/settings/search_zones").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/captiveportal/settings/set_zone/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "interfaces": "opt1"}
    mock_api.get(f"/captiveportal/settings/get_zone/{_UUID}").mock(
        return_value=Response(200, json={"zone": updated})
    )

    params = {**_BASE_PARAMS, "interfaces": "opt1"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["captiveportal_zone"]["interfaces"] == "opt1"


def test_delete_existing_zone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/captiveportal/settings/search_zones").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/captiveportal/settings/del_zone/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "description": "Guest WiFi", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/captiveportal/settings/search_zones").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "description": "Guest WiFi", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/captiveportal/settings/search_zones").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/captiveportal/settings/add_zone").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/captiveportal/settings/get_zone/{_UUID}").mock(
        return_value=Response(200, json={"zone": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/captiveportal/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
