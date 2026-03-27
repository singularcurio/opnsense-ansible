# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Commands

```bash
# Install dependencies (includes ansible-core for module imports)
uv sync

# Run tests
uv run pytest

# Run a single test file
uv run pytest tests/unit/plugins/modules/test_opnsense_cron_job.py

# Lint
uv run ruff check .

# Type check
uv run mypy plugins/
```

## Architecture

**opnsense-ansible** is an Ansible collection (`opnsense.core`) that wraps the
`opnsense-py` client library and exposes OPNsense management as idempotent Ansible
modules.

### Collection layout

```
galaxy.yml                          # collection metadata (namespace: opnsense, name: core)
plugins/
  module_utils/
    opnsense.py                     # shared: client_argument_spec(), build_client()
  modules/
    opnsense_cron_job.py            # reference CRUD module
tests/
  unit/plugins/modules/
    conftest.py                     # sys.path setup for direct module imports
    test_opnsense_cron_job.py
```

### Module anatomy

Each module file contains:

1. **`DOCUMENTATION` / `EXAMPLES` / `RETURN`** — standard Ansible docstrings.
2. **Import block** — try/except to support both installed-collection and
   development-path import of `module_utils.opnsense`.
3. **`run(params, check_mode, client)`** — pure business logic. Returns the dict
   passed to `exit_json`. Separated so tests can call it without `AnsibleModule`.
4. **`run_module()`** — creates `AnsibleModule`, calls `build_client()`, delegates
   to `run()`, handles exceptions.
5. **`main()` / `if __name__ == "__main__"`** — standard Ansible entry points.

### Connection parameters

Every module includes `**client_argument_spec()` in its `argument_spec`. Parameters
resolve in this order (highest priority first):

1. Module params (`host`, `api_key`, `api_secret`, `verify_ssl`, `port`, `https`)
2. Environment variables (`OPNSENSE_HOST`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`,
   `OPNSENSE_VERIFY_SSL`, `OPNSENSE_HTTPS`)

Credentials are best kept in Ansible vault or env vars. Mark them `no_log: true`
in the task when passing as module args.

### Idempotency pattern

- **`state: present`** — find existing resource (by `uuid` if given, otherwise by a
  natural key such as `command`), compare desired vs current fields, update only if
  something differs, or create if not found.
- **`state: absent`** — find existing resource, delete if found, no-op otherwise.
- Honor `check_mode`: report `changed` but make no HTTP mutations.

### Reconfigure pattern

OPNsense stages changes; they take effect only after a `reconfigure` call. Modules
expose a `reconfigure: bool` parameter (default `false`). Set it `true` to apply
changes immediately, or call a dedicated `*_reconfigure` module in a subsequent task.

### Testing approach

Tests use `respx` to mock `httpx` at the transport level (same as opnsense-py).
The `conftest.py` adds `plugins/` and `plugins/modules/` to `sys.path` so modules
can be imported directly without the collection being installed. Tests call `run()`
directly — `AnsibleModule` is never instantiated during unit tests.

### Implemented modules

| Module | Resource | Client | Natural key |
|--------|----------|--------|-------------|
| `opnsense_cron_job` | Cron jobs | `client.cron` | `command` |
| `opnsense_core_tunable` | Sysctl tunables | `client.core` | `tunable` |
| `opnsense_firewall_alias` | Firewall aliases | `client.firewall` | `name` |
| `opnsense_firewall_filter_rule` | Filter rules | `client.firewall` | `description` |
| `opnsense_firewall_dnat_rule` | Port forwards | `client.firewall` | `descr` |
| `opnsense_firewall_snat_rule` | Outbound NAT | `client.firewall` | `description` |
| `opnsense_unbound_host_override` | DNS host overrides | `client.unbound` | `hostname`+`domain` |
| `opnsense_unbound_host_alias` | DNS host aliases | `client.unbound` | `hostname`+`domain` |
| `opnsense_unbound_forward` | DNS forwards/DoT | `client.unbound` | `server` |
| `opnsense_route` | Static routes | `client.routes` | `network` |
| `opnsense_routing_gateway` | Gateways | `client.routing` | `name` |
| `opnsense_syslog_destination` | Syslog remotes | `client.syslog` | `hostname` |
| `opnsense_kea_v4_subnet` | DHCP subnets | `client.kea` | `subnet` |
| `opnsense_kea_v4_reservation` | DHCP reservations | `client.kea` | `ip_address` |
| `opnsense_vlan` | VLAN interfaces | `client.interfaces` | `parent_interface`+`tag` |
| `opnsense_dnsmasq_host` | Dnsmasq hosts | `client.dnsmasq` | `host`+`domain` |
| `opnsense_dnsmasq_domain` | Dnsmasq domain overrides | `client.dnsmasq` | `domain` |
| `opnsense_radvd_entry` | Router advertisements | `client.radvd` | `interface` |
| `opnsense_dhcrelay_destination` | DHCP relay servers | `client.dhcrelay` | `name` |
| `opnsense_dhcrelay_relay` | DHCP relay interfaces | `client.dhcrelay` | `interface` |
| `opnsense_wireguard_server` | WireGuard instances | `client.wireguard` | `name` |
| `opnsense_wireguard_peer` | WireGuard peers | `client.wireguard` | `name` |
| `opnsense_ipsec_connection` | IPsec connections | `client.ipsec` | `description` |
| `opnsense_trafficshaper_pipe` | Traffic shaper pipes | `client.trafficshaper` | `description` |
| `opnsense_trafficshaper_queue` | Traffic shaper queues | `client.trafficshaper` | `description` |
| `opnsense_trafficshaper_rule` | Traffic shaper rules | `client.trafficshaper` | `description` |
| `opnsense_monit_service` | Monit service checks | `client.monit` | `name` |
| `opnsense_monit_alert` | Monit email alerts | `client.monit` | `recipient` |

### Adding a new module

1. Create `plugins/modules/opnsense_<resource>.py` following the anatomy above.
   Use `opnsense_cron_job.py` as the reference implementation.
2. Add tests in `tests/unit/plugins/modules/test_opnsense_<resource>.py`.
3. Update `galaxy.yml` if the module introduces new Python dependencies.
