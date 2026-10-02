# Keel Cloud

Keel Cloud coordinates Keel nodes that their operator owns: it tells the
nodes of a set about each other, so they exchange WireGuard public keys
and endpoints without copy and paste. It runs nothing on the nodes, holds
none of their data and is never required: a standalone Keel node has
every feature a node in Keel Cloud has (handbook decisions 0020 and 0046).
Any operator can run their own instance from the same packages.

The design is handbook decision 0046, "Keel Cloud, version 1 scope". This
repository starts with its Phase A: the API service, and membership and
WireGuard key exchange for the nodes of a set. DNS (Phase B) and the
registry view (Phase C) come later.

## Defaults pending the maintainer's decision

0046 is a proposal. Its recommended answers are the working defaults
here, each kept in one place so that changing one later is cheap:

| Open question in 0046 | Working default |
| --- | --- |
| 1. The language | Python, with Debian 13 packages only; nothing is installed from PyPI and nothing goes into the system Python with pip |
| 2. The scope of an API key | two scopes: an account key, which manages the account, and a narrower enrollment key, which nodes hold |
| 3. Operator confirmation of new peers | required by default; automatic admission is a per-set choice |
| 4. The entry secret's lifetime | one reusable entry secret per set, until the operator rotates it |
| 6. How a node learns of changes | outbound long polling over HTTPS; Keel Cloud never connects to a node |
| Transport | IPv6 first, TLS only |

## License

GPL-3.0, see LICENSE.
