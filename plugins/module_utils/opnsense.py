from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
from typing import Any

from opnsense_py.client import OPNsenseClient


def client_argument_spec() -> dict[str, Any]:
    """Return the shared argument spec for OPNsense connection parameters.

    Include this in every module's ``argument_spec`` via ``**client_argument_spec()``.
    """
    return dict(
        host=dict(type="str", required=False, default=None),
        api_key=dict(type="str", required=False, default=None, no_log=True),
        api_secret=dict(type="str", required=False, default=None, no_log=True),
        verify_ssl=dict(type="bool", required=False, default=None),
        port=dict(type="int", required=False, default=None),
        https=dict(type="bool", required=False, default=True),
    )


def build_client(module: Any) -> OPNsenseClient:
    """Build an :class:`~opnsense_py.client.OPNsenseClient` from module params.

    Parameter resolution order (highest priority first):

    1. Module params (``host``, ``api_key``, ``api_secret``, ``verify_ssl``)
    2. Environment variables (``OPNSENSE_HOST``, ``OPNSENSE_API_KEY``,
       ``OPNSENSE_API_SECRET``, ``OPNSENSE_VERIFY_SSL``)
    """
    host = module.params.get("host") or os.environ.get("OPNSENSE_HOST")
    api_key = module.params.get("api_key") or os.environ.get("OPNSENSE_API_KEY")
    api_secret = module.params.get("api_secret") or os.environ.get("OPNSENSE_API_SECRET")

    if not host:
        module.fail_json(msg="host is required (set via parameter or OPNSENSE_HOST env var)")
    if not api_key:
        module.fail_json(msg="api_key is required (set via parameter or OPNSENSE_API_KEY env var)")
    if not api_secret:
        module.fail_json(
            msg="api_secret is required (set via parameter or OPNSENSE_API_SECRET env var)"
        )

    verify_ssl = module.params.get("verify_ssl")
    if verify_ssl is None:
        env_val = os.environ.get("OPNSENSE_VERIFY_SSL", "true").lower()
        verify_ssl = env_val not in ("false", "0", "no")

    https = module.params.get("https", True)
    if https is None:
        env_val = os.environ.get("OPNSENSE_HTTPS", "true").lower()
        https = env_val not in ("false", "0", "no")

    return OPNsenseClient(
        host=host,
        api_key=api_key,
        api_secret=api_secret,
        verify_ssl=verify_ssl,
        port=module.params.get("port"),
        https=https,
    )
