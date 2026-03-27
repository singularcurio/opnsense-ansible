"""Unit tests for the opnsense_kea_v4_peer module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_kea_v4_peer import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "name": "primary",
    "role": "primary",
    "url": "http://10.0.0.1:8000/",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "name": "primary",
    "role": "primary",
    "url": "http://10.0.0.1:8000/",
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_peer(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_peer").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/kea/dhcpv4/add_peer").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/kea/dhcpv4/get_peer/{_UUID}").mock(
        return_value=Response(200, json={"peer": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["kea_v4_peer"]["uuid"] == _UUID
    assert result["kea_v4_peer"]["name"] == "primary"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_peer").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["kea_v4_peer"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_peer").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["kea_v4_peer"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_peer").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/kea/dhcpv4/set_peer/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "url": "http://10.0.0.2:8000/"}
    mock_api.get(f"/kea/dhcpv4/get_peer/{_UUID}").mock(
        return_value=Response(200, json={"peer": updated})
    )

    params = {**_BASE_PARAMS, "url": "http://10.0.0.2:8000/"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["kea_v4_peer"]["url"] == "http://10.0.0.2:8000/"


def test_delete_existing_peer(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_peer").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/kea/dhcpv4/del_peer/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "name": "primary", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/kea/dhcpv4/search_peer").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "name": "primary", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/kea/dhcpv4/search_peer").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/kea/dhcpv4/add_peer").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/kea/dhcpv4/get_peer/{_UUID}").mock(
        return_value=Response(200, json={"peer": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/kea/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
