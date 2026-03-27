"""Unit tests for the opnsense_unbound_dnsbl module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_unbound_dnsbl import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "description": "Ad blocking list",
    "type": "blacklist",
    "address": "0.0.0.0",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "description": "Ad blocking list",
    "enabled": True,
    "type": "blacklist",
    "lists": None,
    "allowlists": None,
    "blocklists": None,
    "wildcards": None,
    "source_nets": None,
    "address": "0.0.0.0",
    "nxdomain": None,
    "cache_ttl": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_dnsbl(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_dnsbl").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/unbound/settings/add_dnsbl").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/unbound/settings/get_dnsbl/{_UUID}").mock(
        return_value=Response(200, json={"blocklist": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["unbound_dnsbl"]["uuid"] == _UUID
    assert result["unbound_dnsbl"]["description"] == "Ad blocking list"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_dnsbl").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["unbound_dnsbl"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_dnsbl").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["unbound_dnsbl"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_dnsbl").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/unbound/settings/set_dnsbl/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "address": "127.0.0.1"}
    mock_api.get(f"/unbound/settings/get_dnsbl/{_UUID}").mock(
        return_value=Response(200, json={"blocklist": updated})
    )

    params = {**_BASE_PARAMS, "address": "127.0.0.1"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["unbound_dnsbl"]["address"] == "127.0.0.1"


def test_delete_existing_dnsbl(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_dnsbl").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/unbound/settings/del_dnsbl/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "description": "Ad blocking list", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_dnsbl").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "description": "Ad blocking list", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/unbound/settings/search_dnsbl").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/unbound/settings/add_dnsbl").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/unbound/settings/get_dnsbl/{_UUID}").mock(
        return_value=Response(200, json={"blocklist": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/unbound/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
