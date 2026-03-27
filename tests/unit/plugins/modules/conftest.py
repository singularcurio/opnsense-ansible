"""Pytest configuration for Ansible module unit tests.

Because the collection is not installed as a proper Ansible collection during
development, we add the ``plugins/`` directory to ``sys.path`` so that the
fallback import path in each module (``from module_utils.opnsense import ...``)
resolves correctly.

Tests call ``run()`` directly, bypassing ``AnsibleModule`` entirely, so
``ansible-core`` only needs to be importable (not actively used in tests).
"""

from __future__ import annotations

import sys
from pathlib import Path

# plugins/ directory — makes `module_utils.opnsense` importable
# parents: [0]=modules/ [1]=plugins/ [2]=unit/ [3]=tests/ [4]=project root
_plugins_dir = Path(__file__).parents[4] / "plugins"
sys.path.insert(0, str(_plugins_dir))

# plugins/modules/ directory — makes the module files themselves importable
sys.path.insert(0, str(_plugins_dir / "modules"))
