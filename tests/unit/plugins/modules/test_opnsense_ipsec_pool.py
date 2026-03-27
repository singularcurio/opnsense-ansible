"""Unit tests for the opnsense_ipsec_pool module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_ipsec_pool import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "name": "vpn-pool",
    "addrs": "10.10.10.0/24",
    "dns": "8.8.8.8",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "name": "vpn-pool",
    "enabled": True,
    "addrs": "10.10.10.0/24",
    "dns": "8.8.8.8",
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_pool(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/pools/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/ipsec/pools/add").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ipsec/pools/get/{_UUID}").mock(
        return_value=Response(200, json={"Pool": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ipsec_pool"]["uuid"] == _UUID
    assert result["ipsec_pool"]["name"] == "vpn-pool"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/pools/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["ipsec_pool"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/pools/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["ipsec_pool"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/pools/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/ipsec/pools/set/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "dns": "1.1.1.1"}
    mock_api.get(f"/ipsec/pools/get/{_UUID}").mock(
        return_value=Response(200, json={"Pool": updated})
    )

    params = {**_BASE_PARAMS, "dns": "1.1.1.1"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ipsec_pool"]["dns"] == "1.1.1.1"


def test_delete_existing_pool(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/pools/search").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/ipsec/pools/del/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "name": "vpn-pool", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/pools/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "name": "vpn-pool", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/ipsec/pools/search").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/ipsec/pools/add").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ipsec/pools/get/{_UUID}").mock(
        return_value=Response(200, json={"Pool": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/ipsec/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
