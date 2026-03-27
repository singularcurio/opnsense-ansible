"""Unit tests for the opnsense_firewall_one_to_one_rule module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_firewall_one_to_one_rule import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "log": "0",
    "sequence": "1",
    "interface": "wan",
    "type": "binat",
    "source_net": "192.168.1.0/24",
    "source_not": "0",
    "destination_net": "any",
    "destination_not": "0",
    "external": "203.0.113.10",
    "natreflection": "default",
    "categories": "",
    "description": "Server farm 1-to-1 NAT",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "description": "Server farm 1-to-1 NAT",
    "enabled": True,
    "log": None,
    "sequence": None,
    "interface": "wan",
    "type": "binat",
    "source_net": "192.168.1.0/24",
    "source_not": None,
    "destination_net": None,
    "destination_not": None,
    "external": "203.0.113.10",
    "natreflection": None,
    "categories": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_rule(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/one_to_one/search_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/firewall/one_to_one/add_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/one_to_one/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["firewall_one_to_one_rule"]["uuid"] == _UUID
    assert result["firewall_one_to_one_rule"]["description"] == "Server farm 1-to-1 NAT"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/one_to_one/search_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["firewall_one_to_one_rule"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/one_to_one/search_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["firewall_one_to_one_rule"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/one_to_one/search_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/firewall/one_to_one/set_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "external": "203.0.113.20"}
    mock_api.get(f"/firewall/one_to_one/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": updated})
    )

    params = {**_BASE_PARAMS, "external": "203.0.113.20"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["firewall_one_to_one_rule"]["external"] == "203.0.113.20"


def test_delete_existing_rule(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/one_to_one/search_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/firewall/one_to_one/del_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "description": "Server farm 1-to-1 NAT", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/one_to_one/search_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "description": "Server farm 1-to-1 NAT", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/firewall/one_to_one/search_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/firewall/one_to_one/add_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/one_to_one/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/firewall/filter/apply").mock(
        return_value=Response(200, json={"status": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
