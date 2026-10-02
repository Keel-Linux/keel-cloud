# Copyright (c) 2026 KeelLinux maintainers
"""Keel Cloud: membership and WireGuard key exchange for Keel nodes

Handbook decision 0046, Phase A. Three parts share this package:

- keel_cloud.record, keel_cloud.proof and keel_cloud.keys, the formats both
  sides agree on;
- keel_cloud.api, the API service and its command line (keel-cloud-api,
  keel-cloud), packaged as keel-cloud-api;
- keel_cloud.node, the node agent (keel-cloud-node, also reached as
  `keel cloud`), packaged as keel-overlay-cloud.
"""

__version__ = "0.1.0"
