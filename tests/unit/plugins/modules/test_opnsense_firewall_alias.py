"""Unit tests for the opnsense_firewall_alias module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_firewall_alias import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "name": "my_servers",
    "type": "host",
    "enabled": "1",
    "content": "192.168.1.10\n192.168.1.11",
    "description": "My servers",
    "proto": None,
    "interface": None,
    "counters": None,
    "updatefreq": None,
    "categories": None,
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


def test_create_new_alias(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/alias/search_item").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/firewall/alias/add_item").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/firewall/alias/get_item/{_UUID}").mock(
        return_value=Response(200, json={"alias": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "my_servers",
        "enabled": True,
        "type": "host",
        "proto": None,
        "interface": None,
        "counters": None,
        "updatefreq": None,
        "content": "192.168.1.10\n192.168.1.11",
        "categories": None,
        "description": "My servers",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["firewall_alias"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/alias/search_item").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "my_servers",
        "enabled": True,
        "type": "host",
        "proto": None,
        "interface": None,
        "counters": None,
        "updatefreq": None,
        "content": "192.168.1.10\n192.168.1.11",
        "categories": None,
        "description": "My servers",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["firewall_alias"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/alias/search_item").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/firewall/alias/set_item/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "description": "Updated description"}
    mock_api.get(f"/firewall/alias/get_item/{_UUID}").mock(
        return_value=Response(200, json={"alias": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "my_servers",
        "enabled": True,
        "type": "host",
        "proto": None,
        "interface": None,
        "counters": None,
        "updatefreq": None,
        "content": "192.168.1.10\n192.168.1.11",
        "categories": None,
        "description": "Updated description",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/firewall/alias/search_item").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/firewall/alias/del_item/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "name": "my_servers",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
