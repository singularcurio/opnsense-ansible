# Unimplemented Modules

Resources in `opnsense-py` not yet wrapped as Ansible modules.
All follow the same pattern as existing modules in `plugins/modules/`.

---

## Typed-model resources (straightforward — use existing Pydantic models)

**All 16 typed-model resources have been implemented.** See the CLAUDE.md module table.

---

## Dict-based resources (no Pydantic model — use `data: dict` param)

These use `dict[str, Any]` throughout opnsense-py. Use a different module pattern:

- Params: `state`, `uuid` (optional), `name` (natural key for search), `data: dict` (resource fields), `reconfigure`, plus `client_argument_spec()`
- Idempotency: compare only keys present in `data` against existing (patch semantics)
- On create: pass `{"<resource_type>": data}` to the add method
- On update: pass `{"<resource_type>": data}` to the set method

### Interfaces

| Module name | Client method prefix | Natural key | Reconfigure |
|-------------|---------------------|-------------|-------------|
| `opnsense_interfaces_bridge` | `client.interfaces.*_bridge*` | `descr` | `client.interfaces.reconfigure_bridges()` |
| `opnsense_interfaces_gif` | `client.interfaces.*_gif*` | `descr` | `client.interfaces.reconfigure_gifs()` |
| `opnsense_interfaces_gre` | `client.interfaces.*_gre*` | `descr` | `client.interfaces.reconfigure_gres()` |
| `opnsense_interfaces_lagg` | `client.interfaces.*_lagg*` | `descr` | `client.interfaces.reconfigure_laggs()` |
| `opnsense_interfaces_vip` | `client.interfaces.*_vip*` | `subnet` + `interface` | `client.interfaces.reconfigure_vips()` |
| `opnsense_interfaces_vxlan` | `client.interfaces.*_vxlan*` | `descr` | `client.interfaces.reconfigure_vxlans()` |
| `opnsense_interfaces_loopback` | `client.interfaces.*_loopback*` | `descr` | `client.interfaces.reconfigure_loopbacks()` |
| `opnsense_interfaces_neighbor` | `client.interfaces.*_neighbor*` | `ip` | `client.interfaces.reconfigure_neighbors()` |

### KEA DHCPv6

| Module name | Client method prefix | Natural key | Reconfigure |
|-------------|---------------------|-------------|-------------|
| `opnsense_kea_v6_subnet` | `client.kea.*_v6_subnet*` | `subnet` | `client.kea.reconfigure()` |
| `opnsense_kea_v6_reservation` | `client.kea.*_v6_reservation*` | `ip_address` | `client.kea.reconfigure()` |
| `opnsense_kea_v6_peer` | `client.kea.*_v6_peer*` | `name` | `client.kea.reconfigure()` |

### Dnsmasq extras

| Module name | Client method prefix | Natural key | Reconfigure |
|-------------|---------------------|-------------|-------------|
| `opnsense_dnsmasq_range` | `client.dnsmasq.*_range*` | `descr` | `client.dnsmasq.reconfigure()` |
| `opnsense_dnsmasq_tag` | `client.dnsmasq.*_tag*` | `name` | `client.dnsmasq.reconfigure()` |
| `opnsense_dnsmasq_option` | `client.dnsmasq.*_option*` | `descr` | `client.dnsmasq.reconfigure()` |
| `opnsense_dnsmasq_boot` | `client.dnsmasq.*_boot*` | `descr` | `client.dnsmasq.reconfigure()` |

### HAProxy (plugin)

All use `dict[str, Any]`. Client: `client.haproxy`. Reconfigure: `client.haproxy.reconfigure()`.

| Module name | Natural key |
|-------------|-------------|
| `opnsense_haproxy_server` | `name` |
| `opnsense_haproxy_backend` | `name` |
| `opnsense_haproxy_frontend` | `name` |
| `opnsense_haproxy_acl` | `name` |
| `opnsense_haproxy_action` | `name` |

### Auth

Complex — users have passwords, group memberships, expiry dates, etc.
Client: `client.auth`. No reconfigure needed (changes take effect immediately).

| Module name | Natural key | Notes |
|-------------|-------------|-------|
| `opnsense_auth_user` | `username` | Password handling requires special care (no_log) |
| `opnsense_auth_group` | `name` | |

---

## Skipped (not CRUD / operational / read-only)

These are intentionally not implemented as Ansible modules since they don't fit the declarative state model:

| Area | Reason |
|------|--------|
| `diagnostics.*` | Read-only / query operations |
| `firmware.check/update/upgrade` | Imperative operations, not idempotent |
| `firmware.install_package / remove_package` | Use `opnsense_firmware_package` if needed (separate module) |
| `core.reboot / core.halt` | Imperative — use `ansible.builtin.reboot` |
| `core.backup.*` | Operational |
| `ipsec.search_sessions / connect_session` | Runtime state, not config |
| `wireguard.key_pair` | Key generation utility |
| `openvpn.gen_key / export_*` | Key generation / export utilities |
| `captiveportal.sessions / vouchers` | Runtime operations |
| `ids.reload_rules / update_rules` | Operational trigger |
| `unbound.dump_cache / flush_*` | Operational |
| `trust.*` | Certificate management — complex, consider dedicated module |

---

## Implementation notes

### Dict-based module template

```python
def run(params, check_mode, client) -> dict:
    state = params.get("state", "present")
    uuid = params.get("uuid")
    name = params.get("name")
    data = params.get("data") or {}

    if uuid:
        existing_uuid, existing = _find_by_uuid(client, uuid)
    elif name:
        existing_uuid, existing = _find_by_name(client, name)
    else:
        existing_uuid, existing = None, None

    if state == "absent":
        if existing_uuid is None:
            return {"changed": False}
        if not check_mode:
            client.MODULE.del_RESOURCE(existing_uuid)
            if params.get("reconfigure"):
                client.MODULE.reconfigure()
        return {"changed": True}

    if existing_uuid is None:
        if check_mode:
            return {"changed": True, "RESOURCE": None}
        resp = client.MODULE.add_RESOURCE({"RESOURCE": data})
        new_uuid = resp.uuid
        if params.get("reconfigure"):
            client.MODULE.reconfigure()
        result = client.MODULE.get_RESOURCE(new_uuid)
        result["uuid"] = new_uuid
        return {"changed": True, "RESOURCE": result}

    # Patch semantics: only compare keys present in data
    if not any(existing.get(k) != v for k, v in data.items() if v is not None):
        existing["uuid"] = existing_uuid
        return {"changed": False, "RESOURCE": existing}

    if not check_mode:
        client.MODULE.set_RESOURCE(existing_uuid, {"RESOURCE": data})
        if params.get("reconfigure"):
            client.MODULE.reconfigure()
    result = client.MODULE.get_RESOURCE(existing_uuid)
    result["uuid"] = existing_uuid
    return {"changed": True, "RESOURCE": result}
```
