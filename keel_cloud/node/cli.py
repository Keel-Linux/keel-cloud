# Copyright (c) 2026 KeelLinux maintainers
"""keel-cloud-node, also reached as `keel cloud`

    keel-cloud-node entry-secret        print the set's entry secret, made
                                        here on the set's first node
    keel-cloud-node enroll              register this node in its set
    keel-cloud-node sync [--wait N]     admit what the set proposes and
                                        write the pinned peers into the spec
    keel-cloud-node confirm KEY --account-key-file FILE
                                        the operator admits a pending node
    keel-cloud-node status              the set as Keel Cloud and this node
                                        see it
    keel-cloud-node run                 enroll and long poll for ever, the
                                        keel-cloud-node service
"""

import argparse
import os
import sys

from keel_cloud.node import NodeError
from keel_cloud.node.agent import STATE_DIR_DEFAULT, WAIT, Agent
from keel_cloud.node.client import CloudError
from keel_cloud.node.spec import SPEC_DEFAULT, SPEC_ENV


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keel-cloud-node",
        description="This node's side of Keel Cloud: membership and"
        " WireGuard key exchange for the overlay of its set")
    parser.add_argument("--spec", default=os.environ.get(SPEC_ENV,
                                                         SPEC_DEFAULT),
                        metavar="FILE", help=f"the instance spec (default:"
                        f" ${SPEC_ENV} or {SPEC_DEFAULT})")
    parser.add_argument("--state-dir", default=STATE_DIR_DEFAULT,
                        metavar="DIR", help="where the pinned peers are kept"
                        f" (default: {STATE_DIR_DEFAULT})")
    actions = parser.add_subparsers(dest="action", metavar="ACTION",
                                    required=True)
    actions.add_parser("entry-secret", help="print the set's entry secret,"
                       " making it when the spec's file does not exist")
    enroll = actions.add_parser("enroll", help="register this node")
    enroll.add_argument("--endpoint", metavar="HOST:PORT",
                        help="the endpoint peers reach this node at"
                        " (default: its best address, IPv6 first)")
    sync = actions.add_parser("sync", help="admit and write peers")
    sync.add_argument("--wait", type=int, default=0, metavar="SECONDS",
                      help=f"long poll for a change first, at most {WAIT}")
    sync.add_argument("--since", type=int, default=0, metavar="REVISION",
                      help="the revision already seen, for --wait")
    confirm = actions.add_parser("confirm", help="admit a pending node, with"
                                 " the account key")
    confirm.add_argument("public_key")
    confirm.add_argument("--account-key-file", required=True, metavar="FILE",
                         help="a file holding the account key, root's and"
                         " mode 0600")
    actions.add_parser("status", help="the set and its peers")
    actions.add_parser("run", help="enroll, then long poll for changes")
    return parser


def main(argv: list[str] | None = None, agent_factory=Agent) -> int:
    args = build_parser().parse_args(argv)
    agent = agent_factory(args.spec, args.state_dir)
    try:
        if args.action == "entry-secret":
            agent.entry_secret()
        elif args.action == "enroll":
            agent.enroll(args.endpoint)
        elif args.action == "sync":
            agent.sync(args.since, max(0, min(args.wait, WAIT)))
        elif args.action == "confirm":
            agent.confirm(args.public_key, args.account_key_file)
        elif args.action == "status":
            agent.status()
        else:
            agent.run()
    except (NodeError, CloudError) as failure:
        print(f"keel-cloud-node: {failure}", file=sys.stderr)
        return 1
    return 0
