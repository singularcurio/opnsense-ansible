"""Unit tests for the opnsense_unbound_forward module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_unbound_forward import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "type": "dot",
    "server": "1.1.1.1",
    "port": "853",
    "verify": "cloudflare-dns.com",
    "description": "Cloudflare DoT",
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


def test_create_new_forward(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_forward").mock(
        return_value=Response(200, json={"total": 0, "rowCount": 500, "current": 1, "rows": []})
    )
    mock_api.post("/unbound/settings/add_forward").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/unbound/settings/get_forward/{_UUID}").mock(
        return_value=Response(200, json={"forward": _ITEM_RESPONSE})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "type": "dot",
        "domain": None,
        "server": "1.1.1.1",
        "dns_port": "853",
        "verify": "cloudflare-dns.com",
        "forward_tcp_upstream": None,
        "forward_first": None,
        "description": "Cloudflare DoT",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["forward"]["uuid"] == _UUID


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_forward").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "type": "dot",
        "domain": None,
        "server": "1.1.1.1",
        "dns_port": "853",
        "verify": "cloudflare-dns.com",
        "forward_tcp_upstream": None,
        "forward_first": None,
        "description": "Cloudflare DoT",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["forward"]["uuid"] == _UUID


def test_update_when_changed(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_forward").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/unbound/settings/set_forward/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "verify": "dns.google"}
    mock_api.get(f"/unbound/settings/get_forward/{_UUID}").mock(
        return_value=Response(200, json={"forward": updated})
    )

    params = {
        **_CONN,
        "state": "present",
        "uuid": None,
        "enabled": True,
        "type": "dot",
        "domain": None,
        "server": "1.1.1.1",
        "dns_port": "853",
        "verify": "dns.google",
        "forward_tcp_upstream": None,
        "forward_first": None,
        "description": "Cloudflare DoT",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_existing(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/unbound/settings/search_forward").mock(
        return_value=Response(200, json={"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]})
    )
    mock_api.post(f"/unbound/settings/del_forward/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {
        **_CONN,
        "state": "absent",
        "uuid": None,
        "server": "1.1.1.1",
        "reconfigure": False,
    }
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
