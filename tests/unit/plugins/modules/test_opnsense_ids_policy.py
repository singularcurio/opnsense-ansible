"""Unit tests for the opnsense_ids_policy module."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from opnsense_py.client import OPNsenseClient
from opnsense_ids_policy import run  # type: ignore[import]

_BASE = "https://opnsense.test:443/api"
_UUID = "a1b2c3d4-0000-0000-0000-000000000001"

_ITEM_RESPONSE = {
    "uuid": _UUID,
    "enabled": "1",
    "prio": 1,
    "action": "alert",
    "rulesets": "",
    "content": "",
    "new_action": "alert",
    "description": "Block known malware",
}

_SEARCH_HIT = {"total": 1, "rowCount": 500, "current": 1, "rows": [_ITEM_RESPONSE]}
_SEARCH_EMPTY = {"total": 0, "rowCount": 500, "current": 1, "rows": []}

_BASE_PARAMS = {
    "state": "present",
    "uuid": None,
    "description": "Block known malware",
    "enabled": True,
    "prio": None,
    "action": "alert",
    "rulesets": None,
    "content": None,
    "new_action": None,
    "reconfigure": False,
}


@pytest.fixture()
def client() -> OPNsenseClient:
    return OPNsenseClient(host="opnsense.test", api_key="key", api_secret="secret")


@pytest.fixture()
def mock_api():
    with respx.mock(base_url=_BASE, assert_all_called=False) as router:
        yield router


def test_create_new_policy(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_policy").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/ids/settings/add_policy").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ids/settings/get_policy/{_UUID}").mock(
        return_value=Response(200, json={"policy": _ITEM_RESPONSE})
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ids_policy"]["uuid"] == _UUID
    assert result["ids_policy"]["description"] == "Block known malware"


def test_create_check_mode(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_policy").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    result = run(_BASE_PARAMS, check_mode=True, client=client)

    assert result["changed"] is True
    assert result["ids_policy"] is None


def test_no_update_when_identical(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_policy").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )

    result = run(_BASE_PARAMS, check_mode=False, client=client)

    assert result["changed"] is False
    assert result["ids_policy"]["uuid"] == _UUID


def test_update_changed_field(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_policy").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/ids/settings/set_policy/{_UUID}").mock(
        return_value=Response(200, json={"result": "saved"})
    )
    updated = {**_ITEM_RESPONSE, "action": "drop"}
    mock_api.get(f"/ids/settings/get_policy/{_UUID}").mock(
        return_value=Response(200, json={"policy": updated})
    )

    params = {**_BASE_PARAMS, "action": "drop"}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True
    assert result["ids_policy"]["action"] == "drop"


def test_delete_existing_policy(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_policy").mock(
        return_value=Response(200, json=_SEARCH_HIT)
    )
    mock_api.post(f"/ids/settings/del_policy/{_UUID}").mock(
        return_value=Response(200, json={"result": "deleted"})
    )

    params = {"state": "absent", "uuid": None, "description": "Block known malware", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is True


def test_absent_already_gone(client: OPNsenseClient, mock_api: respx.MockRouter) -> None:
    mock_api.post("/ids/settings/search_policy").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )

    params = {"state": "absent", "uuid": None, "description": "Block known malware", "reconfigure": False}
    result = run(params, check_mode=False, client=client)

    assert result["changed"] is False


def test_reconfigure_called_on_create(
    client: OPNsenseClient, mock_api: respx.MockRouter
) -> None:
    mock_api.post("/ids/settings/search_policy").mock(
        return_value=Response(200, json=_SEARCH_EMPTY)
    )
    mock_api.post("/ids/settings/add_policy").mock(
        return_value=Response(200, json={"result": "saved", "uuid": _UUID})
    )
    mock_api.get(f"/ids/settings/get_policy/{_UUID}").mock(
        return_value=Response(200, json={"policy": _ITEM_RESPONSE})
    )
    reconfigure_route = mock_api.post("/ids/service/reconfigure").mock(
        return_value=Response(200, json={"result": "ok"})
    )

    params = {**_BASE_PARAMS, "reconfigure": True}
    run(params, check_mode=False, client=client)

    assert reconfigure_route.called
