"""Unit tests for the opnsense_ids_user_rule module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_ids_user_rule import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "source": "any",
    "destination": "any",
    "fingerprint": "",
    "description": "Block test traffic",
    "action": "alert",
    "bypass": "0",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "description": "Block test traffic",
    "enabled": True,
    "source": "any",
    "destination": "any",
    "fingerprint": None,
    "action": "alert",
    "bypass": None,
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
    mock_api.post("/ids/settings/search_user_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/ids/settings/add_user_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ids/settings/get_user_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ids_user_rule"]["uuid"] == _UUID
    assert result["ids_user_rule"]["description"] == "Block test traffic"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_user_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["ids_user_rule"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_user_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["ids_user_rule"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_user_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/ids/settings/set_user_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "action": "drop"}
    mock_api.get(f"/ids/settings/get_user_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": updated})
    )

    params = {**_BASE_PARAMS, "action": "drop"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ids_user_rule"]["action"] == "drop"


def test_delete_existing_rule(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_user_rule").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/ids/settings/del_user_rule/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "description": "Block test traffic", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_user_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "description": "Block test traffic", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/ids/settings/search_user_rule").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/ids/settings/add_user_rule").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ids/settings/get_user_rule/{_UUID}").mock(
        return_value=Response(200, json={"rule": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/ids/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
