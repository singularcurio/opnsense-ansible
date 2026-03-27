"""Unit tests for the opnsense_firewall_npt_rule module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_firewall_npt_rule import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "log": "0",
    "sequence": "1",
    "interface": "wan",
    "source_net": "fd00::/48",
    "destination_net": "2001:db8::/48",
    "trackif": "",
    "categories": "",
    "description": "IPv6 prefix translation",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "description": "IPv6 prefix translation",
    "enabled": True,
    "log": None,
    "sequence": None,
    "interface": "wan",
    "source_net": "fd00::/48",
    "destination_net": "2001:db8::/48",
    "trackif": None,
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
    mock_api.post("/firewall/npt/search_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/firewall/npt/add_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/npt/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["firewall_npt_rule"]["uuid"] == _UUID
    assert result["firewall_npt_rule"]["description"] == "IPv6 prefix translation"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/npt/search_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["firewall_npt_rule"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/npt/search_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["firewall_npt_rule"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/npt/search_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/firewall/npt/set_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "interface": "opt1"}
    mock_api.get(f"/firewall/npt/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": updated})
    )

    params = {**_BASE_PARAMS, "interface": "opt1"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["firewall_npt_rule"]["interface"] == "opt1"


def test_delete_existing_rule(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/npt/search_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/firewall/npt/del_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "description": "IPv6 prefix translation", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/npt/search_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "description": "IPv6 prefix translation", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/firewall/npt/search_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/firewall/npt/add_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/npt/get_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/firewall/filter/apply").mock(
        return_value=Response(200, json={"status": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
