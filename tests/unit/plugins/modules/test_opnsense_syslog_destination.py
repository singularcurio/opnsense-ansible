"""Unit tests for the opnsense_syslog_destination module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_syslog_destination import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "hostname": "syslog.example.com",
    "transport": "udp4",
    "port": "514",
    "level": "info",
    "description": "Central syslog server",
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
    mock_api.post("/syslog/settings/search_destinations").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/syslog/settings/add_destination").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/syslog/settings/get_destination/{_UUID}").mock(
        return_value=Response(200, json={"destination": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "transport": "udp4",
        "program": None,
        "level": "info",
        "facility": None,
        "hostname": "syslog.example.com",
        "certificate": None,
        "syslog_port": "514",
        "rfc5424": None,
        "description": "Central syslog server",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["syslog_destination"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/syslog/settings/search_destinations").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "transport": "udp4",
        "program": None,
        "level": "info",
        "facility": None,
        "hostname": "syslog.example.com",
        "certificate": None,
        "syslog_port": "514",
        "rfc5424": None,
        "description": "Central syslog server",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["syslog_destination"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/syslog/settings/search_destinations").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/syslog/settings/set_destination/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "transport": "tcp4"}
    mock_api.get(f"/syslog/settings/get_destination/{_UUID}").mock(
        return_value=Response(200, json={"destination": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "transport": "tcp4",
        "program": None,
        "level": "info",
        "facility": None,
        "hostname": "syslog.example.com",
        "certificate": None,
        "syslog_port": "514",
        "rfc5424": None,
        "description": "Central syslog server",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/syslog/settings/search_destinations").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/syslog/settings/del_destination/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "hostname": "syslog.example.com",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
