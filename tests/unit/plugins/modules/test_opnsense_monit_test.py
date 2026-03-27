"""Unit tests for the opnsense_monit_test module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_monit_test import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "name": "cpu-check",
    "type": "SystemResource",
    "condition": "cpu usage > 90%",
    "action": "alert",
    "path": "",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "name": "cpu-check",
    "type": "SystemResource",
    "condition": "cpu usage > 90%",
    "action": "alert",
    "path": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_test(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_test").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/monit/settings/add_test").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/monit/settings/get_test/{_UUID}").mock(
        return_value=Response(200, json={"test": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["monit_test"]["uuid"] == _UUID
    assert result["monit_test"]["name"] == "cpu-check"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_test").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["monit_test"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_test").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["monit_test"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_test").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/monit/settings/set_test/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "condition": "cpu usage > 95%"}
    mock_api.get(f"/monit/settings/get_test/{_UUID}").mock(
        return_value=Response(200, json={"test": updated})
    )

    params = {**_BASE_PARAMS, "condition": "cpu usage > 95%"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["monit_test"]["condition"] == "cpu usage > 95%"


def test_delete_existing_test(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_test").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/monit/settings/del_test/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "name": "cpu-check", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/monit/settings/search_test").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "name": "cpu-check", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/monit/settings/search_test").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/monit/settings/add_test").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/monit/settings/get_test/{_UUID}").mock(
        return_value=Response(200, json={"test": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/monit/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
