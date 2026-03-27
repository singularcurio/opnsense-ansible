"""Unit tests for the opnsense_ipsec_child module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_ipsec_child import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "connection": "",
    "reqid": 0,
    "esp_proposals": "",
    "sha256_96": "0",
    "start_action": "start",
    "close_action": "none",
    "dpd_action": "clear",
    "mode": "tunnel",
    "policies": "1",
    "local_ts": "0.0.0.0/0",
    "remote_ts": "0.0.0.0/0",
    "rekey_time": 3600,
    "description": "Child SA tunnel",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "description": "Child SA tunnel",
    "enabled": True,
    "connection": None,
    "reqid": None,
    "esp_proposals": None,
    "sha256_96": None,
    "start_action": "start",
    "close_action": None,
    "dpd_action": None,
    "mode": "tunnel",
    "policies": None,
    "local_ts": "0.0.0.0/0",
    "remote_ts": "0.0.0.0/0",
    "rekey_time": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_child(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_child").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/ipsec/connections/add_child").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ipsec/connections/get_child/{_UUID}").mock(
        return_value=Response(200, json={"child": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ipsec_child"]["uuid"] == _UUID
    assert result["ipsec_child"]["description"] == "Child SA tunnel"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_child").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["ipsec_child"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_child").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["ipsec_child"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_child").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/ipsec/connections/set_child/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "mode": "transport"}
    mock_api.get(f"/ipsec/connections/get_child/{_UUID}").mock(
        return_value=Response(200, json={"child": updated})
    )

    params = {**_BASE_PARAMS, "mode": "transport"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ipsec_child"]["mode"] == "transport"


def test_delete_existing_child(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_child").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/ipsec/connections/del_child/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "description": "Child SA tunnel", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_child").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "description": "Child SA tunnel", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/ipsec/connections/search_child").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/ipsec/connections/add_child").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ipsec/connections/get_child/{_UUID}").mock(
        return_value=Response(200, json={"child": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/ipsec/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
