"""Unit tests for the opnsense_unbound_acl module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_unbound_acl import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "name": "trusted-networks",
    "action": "allow",
    "networks": "192.168.0.0/16",
    "description": "",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "name": "trusted-networks",
    "enabled": True,
    "action": "allow",
    "networks": "192.168.0.0/16",
    "description": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_acl(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_acl").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/unbound/settings/add_acl").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/unbound/settings/get_acl/{_UUID}").mock(
        return_value=Response(200, json={"acl": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["unbound_acl"]["uuid"] == _UUID
    assert result["unbound_acl"]["name"] == "trusted-networks"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_acl").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["unbound_acl"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_acl").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["unbound_acl"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_acl").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/unbound/settings/set_acl/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "networks": "10.0.0.0/8"}
    mock_api.get(f"/unbound/settings/get_acl/{_UUID}").mock(
        return_value=Response(200, json={"acl": updated})
    )

    params = {**_BASE_PARAMS, "networks": "10.0.0.0/8"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["unbound_acl"]["networks"] == "10.0.0.0/8"


def test_delete_existing_acl(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_acl").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/unbound/settings/del_acl/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "name": "trusted-networks", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_acl").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "name": "trusted-networks", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/unbound/settings/search_acl").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/unbound/settings/add_acl").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/unbound/settings/get_acl/{_UUID}").mock(
        return_value=Response(200, json={"acl": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/unbound/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
