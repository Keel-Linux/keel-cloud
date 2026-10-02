# Copyright (c) 2026 KeelLinux maintainers
"""The node agent of Keel Cloud: keel-cloud-node, or `keel cloud`

It reads the spec's `cloud` section, registers this node, and writes the
peers its set admits into this node's own
`network.overlay.wireguard.peers`. It never writes WireGuard's
configuration: `keel spec apply --system` converges the spec under the
confirmation window of handbook decision 0018.
"""


class NodeError(Exception):
    """Something the operator has to fix; the message says what"""
