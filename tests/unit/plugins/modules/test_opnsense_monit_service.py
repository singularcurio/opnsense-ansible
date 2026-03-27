"""Unit tests for the opnsense_monit_service module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_monit_service import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "name": "nginx",
    "type": "process",
    "pidfile": "/var/run/nginx.pid",
    "start": "/usr/sbin/service nginx start",
    "stop": "/usr/sbin/service nginx stop",
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


def test_create_new_service(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_service").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/monit/settings/add_service").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/monit/settings/get_service/{_UUID}").mock(
        return_value=Response(200, json={"service": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "nginx",
        "enabled": True,
        "type": "process",
        "pidfile": "/var/run/nginx.pid",
        "match": None,
        "path": None,
        "timeout": None,
        "starttimeout": None,
        "address": None,
        "interface": None,
        "start": "/usr/sbin/service nginx start",
        "stop": "/usr/sbin/service nginx stop",
        "tests": None,
        "depends": None,
        "polltime": None,
        "description": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["monit_service"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_service").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "nginx",
        "enabled": True,
        "type": "process",
        "pidfile": "/var/run/nginx.pid",
        "match": None,
        "path": None,
        "timeout": None,
        "starttimeout": None,
        "address": None,
        "interface": None,
        "start": "/usr/sbin/service nginx start",
        "stop": "/usr/sbin/service nginx stop",
        "tests": None,
        "depends": None,
        "polltime": None,
        "description": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["monit_service"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_service").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/monit/settings/set_service/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "pidfile": "/var/run/nginx2.pid"}
    mock_api.get(f"/monit/settings/get_service/{_UUID}").mock(
        return_value=Response(200, json={"service": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "name": "nginx",
        "enabled": True,
        "type": "process",
        "pidfile": "/var/run/nginx2.pid",
        "match": None,
        "path": None,
        "timeout": None,
        "starttimeout": None,
        "address": None,
        "interface": None,
        "start": "/usr/sbin/service nginx start",
        "stop": "/usr/sbin/service nginx stop",
        "tests": None,
        "depends": None,
        "polltime": None,
        "description": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_service").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/monit/settings/del_service/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "name": "nginx",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
