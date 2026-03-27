# Unimplemented Modules

Resources in `opnsense-py` not yet wrapped as Ansible modules.
All follow the same pattern as existing modules in `plugins/modules/`.

---

## Typed-model resources (straightforward — use existing Pydantic models)

Implement exactly like `opnsense_cron_job.py`. The model fields are the module params.

| Module name | Model | Client | Natural key | Reconfigure call |
|-------------|-------|--------|-------------|-----------------|
| `opnsense_captiveportal_zone` | `CaptivePortalZone` | `client.captiveportal` | `description` | `client.captiveportal.reconfigure()` |
| `opnsense_firewall_category` | `FirewallCategory` | `client.firewall` | `name` | `client.firewall.apply()` |
| `opnsense_firewall_npt_rule` | `NPTRule` | `client.firewall` | `description` | `client.firewall.apply()` |
| `opnsense_firewall_one_to_one_rule` | `OneToOneRule` | `client.firewall` | `description` | `client.firewall.apply()` |
| `opnsense_ids_policy` | `IDSPolicy` | `client.ids` | `description` | `client.ids.reconfigure()` |
| `opnsense_ids_user_rule` | `IDSUserRule` | `client.ids` | `description` | `client.ids.reconfigure()` |
| `opnsense_ipsec_child` | `IPsecChild` | `client.ipsec` | `description` | `client.ipsec.reconfigure()` |
| `opnsense_ipsec_local` | `IPsecLocal` | `client.ipsec` | `description` | `client.ipsec.reconfigure()` |
| `opnsense_ipsec_remote` | `IPsecRemote` | `client.ipsec` | `description` | `client.ipsec.reconfigure()` |
| `opnsense_ipsec_pool` | `IPsecPool` | `client.ipsec` | `name` | `client.ipsec.reconfigure()` |
| `opnsense_kea_v4_peer` | `KeaHaPeer` | `client.kea` | `name` | `client.kea.reconfigure()` |
| `opnsense_monit_test` | `MonitTest` | `client.monit` | `name` | `client.monit.reconfigure()` |
| `opnsense_openvpn_instance` | `OpenVPNInstance` | `client.openvpn` | `description` | `client.openvpn.reconfigure()` (check method name) |
| `opnsense_openvpn_overwrite` | `OpenVPNOverwrite` | `client.openvpn` | `common_name` | `client.openvpn.reconfigure()` |
| `opnsense_unbound_acl` | `UnboundAcl` | `client.unbound` | `name` | `client.unbound.reconfigure()` |
| `opnsense_unbound_dnsbl` | `UnboundDnsbl` | `client.unbound` | `description` | `client.unbound.reconfigure()` |

### Method names to verify before implementing

```python
# captiveportal
client.captiveportal.search_zones / get_zone / add_zone / set_zone / del_zone

# firewall categories
client.firewall.search_categories / get_category / add_category / set_category / del_category

# firewall NPT
client.firewall.search_npt_rules / get_npt_rule / add_npt_rule / set_npt_rule / del_npt_rule

# firewall one-to-one
client.firewall.search_one_to_one_rules / get_one_to_one_rule / add_one_to_one_rule / set_one_to_one_rule / del_one_to_one_rule

# IDS
client.ids.search_policies / get_policy / add_policy / set_policy / del_policy
client.ids.search_user_rules / get_user_rule / add_user_rule / set_user_rule / del_user_rule

# IPsec
client.ipsec.search_children / get_child / add_child / set_child / del_child
client.ipsec.search_locals / get_local / add_local / set_local / del_local
client.ipsec.search_remotes / get_remote / add_remote / set_remote / del_remote
client.ipsec.search_pools / get_pool / add_pool / set_pool / del_pool

# Kea HA peer
client.kea.search_v4_peers / get_v4_peer / add_v4_peer / set_v4_peer / del_v4_peer

# Monit test
client.monit.search_tests / get_test / add_test / set_test / del_test

# OpenVPN
client.openvpn.search_instances / get_instance / add_instance / set_instance / del_instance
client.openvpn.search_client_overwrites / get_client_overwrite / add_client_overwrite / set_client_overwrite / del_client_overwrite

# Unbound
client.unbound.search_acls / get_acl / add_acl / set_acl / del_acl
client.unbound.search_dnsbl / get_dnsbl / add_dnsbl / set_dnsbl / del_dnsbl
```

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
