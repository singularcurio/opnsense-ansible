"""Unit tests for the opnsense_ipsec_connection module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_ipsec_connection import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "description": "Site-to-site VPN",
    "enabled": "1",
    "remote_addrs": "203.0.113.1",
    "version": "ikev2",
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


def test_create_new_connection(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_connection").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/ipsec/connections/add_connection").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ipsec/connections/get_connection/{_UUID}").mock(
        return_value=Response(200, json={"connection": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Site-to-site VPN",
        "enabled": True,
        "proposals": None,
        "unique": None,
        "aggressive": None,
        "version": "ikev2",
        "mobike": None,
        "local_addrs": None,
        "local_port": None,
        "remote_addrs": "203.0.113.1",
        "remote_port": None,
        "encap": None,
        "reauth_time": None,
        "rekey_time": None,
        "over_time": None,
        "dpd_delay": None,
        "dpd_timeout": None,
        "pools": None,
        "send_certreq": None,
        "send_cert": None,
        "keyingtries": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ipsec_connection"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_connection").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Site-to-site VPN",
        "enabled": True,
        "proposals": None,
        "unique": None,
        "aggressive": None,
        "version": "ikev2",
        "mobike": None,
        "local_addrs": None,
        "local_port": None,
        "remote_addrs": "203.0.113.1",
        "remote_port": None,
        "encap": None,
        "reauth_time": None,
        "rekey_time": None,
        "over_time": None,
        "dpd_delay": None,
        "dpd_timeout": None,
        "pools": None,
        "send_certreq": None,
        "send_cert": None,
        "keyingtries": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["ipsec_connection"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_connection").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/ipsec/connections/set_connection/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "remote_addrs": "203.0.113.2"}
    mock_api.get(f"/ipsec/connections/get_connection/{_UUID}").mock(
        return_value=Response(200, json={"connection": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "description": "Site-to-site VPN",
        "enabled": True,
        "proposals": None,
        "unique": None,
        "aggressive": None,
        "version": "ikev2",
        "mobike": None,
        "local_addrs": None,
        "local_port": None,
        "remote_addrs": "203.0.113.2",
        "remote_port": None,
        "encap": None,
        "reauth_time": None,
        "rekey_time": None,
        "over_time": None,
        "dpd_delay": None,
        "dpd_timeout": None,
        "pools": None,
        "send_certreq": None,
        "send_cert": None,
        "keyingtries": None,
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ipsec/connections/search_connection").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/ipsec/connections/del_connection/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "description": "Site-to-site VPN",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
