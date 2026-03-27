"""Unit tests for the opnsense_dhcrelay_destination module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_dhcrelay_destination import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "name": "primary-dhcp",
    "server": "10.0.0.1",
}

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


def test_create_new_destination(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dhcrelay/settings/search_dest").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/dhcrelay/settings/add_dest").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/dhcrelay/settings/get_dest/{_UUID}").mock(
        return_value=Response(200, json={"destination": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "primary-dhcp",
        "server": "10.0.0.1",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["dhcrelay_destination"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dhcrelay/settings/search_dest").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "primary-dhcp",
        "server": "10.0.0.1",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["dhcrelay_destination"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dhcrelay/settings/search_dest").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/dhcrelay/settings/set_dest/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "server": "10.0.0.2"}
    mock_api.get(f"/dhcrelay/settings/get_dest/{_UUID}").mock(
        return_value=Response(200, json={"destination": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "primary-dhcp",
        "server": "10.0.0.2",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/dhcrelay/settings/search_dest").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/dhcrelay/settings/del_dest/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "name": "primary-dhcp",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
