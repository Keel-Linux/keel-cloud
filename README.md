# Keel Cloud

Keel Cloud coordinates Keel nodes that their operator owns: it tells the
nodes of a set about each other, so they exchange WireGuard public keys
and endpoints without copy and paste. It runs nothing on the nodes, holds
none of their data and is never required: a standalone Keel node has
every feature a node in Keel Cloud has (handbook decisions 0020 and 0046).
Any operator can run their own instance from the same packages.

The design is handbook decision 0046, "Keel Cloud, version 1 scope". This
repository holds its **Phase A**: the API service, and membership and
WireGuard key exchange for the nodes of a set. DNS with a health check
(Phase B) and the registry view (Phase C) come later and are not here.

## Defaults pending the maintainer's decision

0046 is a proposal. Its recommended answers are the working defaults
here, each kept in one place so that changing one later is cheap:

| Open question in 0046 | Working default | Where it lives |
| --- | --- | --- |
| 1. The language | Python, with Debian 13 packages only (`python3-aiohttp`, `python3-yaml`); nothing is installed from PyPI and nothing goes into the system Python with pip | `debian/control` |
| 2. The scope of an API key | two scopes: an **account key**, which manages the account, and a narrower **enrollment key**, which nodes hold and which can only register nodes and read their sets | `keel_cloud/keys.py`, the `principal(...)` scopes in `keel_cloud/api/app.py` |
| 3. Operator confirmation of new peers | **required by default**; automatic admission is a per-set choice (`keel-cloud set auto-admit`) | `sets.auto_admit` in `keel_cloud/api/store.py` |
| 4. The entry secret's lifetime | **one reusable entry secret per set**, until the operator rotates it; rotation does not affect peers already pinned | `keel_cloud/proof.py` |
| 6. How a node learns of changes | **outbound long polling** over HTTPS, at most 55 seconds a request, and a retry every 60 seconds when the service is unreachable; Keel Cloud never connects to a node | `MAX_WAIT` in `keel_cloud/api/app.py`, `WAIT` and `RETRY` in `keel_cloud/node/agent.py` |
| Transport | **IPv6 first, TLS only**: the service listens on `[::]:8443` with TLS and has no plain HTTP listener | `conf/api.conf`, `keel_cloud/api/server.py` |

Questions 5, 7 and 8 of 0046 concern Phase B or are already answered (the
repository exists).

## The packages

One Debian source package (0039), three binary packages:

| Package | Installed on | What it is |
| --- | --- | --- |
| `python3-keel-cloud` | both sides | the Python package `keel_cloud`: the node record, the entry secret proof, the key formats, the service and the agent |
| `keel-cloud-api` | the Keel Cloud machine | `keel-cloud-api`, the service, as the systemd unit `keel-cloud-api.service` running as the system user `keel-cloud`; `keel-cloud`, its command line; `/etc/keel-cloud/api.conf` |
| `keel-overlay-cloud` | a Keel node | `keel-cloud-node`, the node agent, also run as `keel cloud` (keel 0.16.0 or later), and `keel-cloud-node.service`, installed **disabled** |

## The API, version 1

Every request but the health check carries an API key as a bearer token.
Errors are JSON, `{"error": "..."}`.

| Method and path | Key | What it does |
| --- | --- | --- |
| `GET /v1/health` | none | `{"status": "ok", "version": ...}` |
| `POST /v1/keys` | account | make a key, an enrollment key by default; it is returned once |
| `GET /v1/sets` | account | the account's sets |
| `PATCH /v1/sets/{set}` | account | `{"auto_admit": true}` or `false` |
| `POST /v1/sets/{set}/peers` | enrollment or account | register or update a node: `{"record": ..., "proof": ...}`; the set is made on the first registration |
| `GET /v1/sets/{set}/peers` | enrollment or account | the set's nodes, each with its record, its proof, its status (`pending` or `confirmed`) and whether it is admitted; `?since=REVISION&wait=SECONDS` is the long poll |
| `POST /v1/sets/{set}/peers/confirm` | account | `{"public_key": ...}`: the operator admits a pending node |

Accounts and the first keys are made on the instance with the command
line, which runs as `keel-cloud` even when started as root:

```
keel-cloud account create acme          # prints the account key, once
keel-cloud key create acme              # prints an enrollment key, once
keel-cloud peer list acme shop
keel-cloud peer confirm acme shop <public key>
keel-cloud set auto-admit acme shop on
keel-cloud key revoke acme <id>
```

A node record is public information only: the WireGuard public key, the
overlay addresses, the endpoint, the set, and the appliance, role and site
labels (`keel_cloud/record.py`).

## The trust model

What the service stores (`keel_cloud/api/store.py`, SQLite): accounts, the
**SHA-256 of each API key** and never the key, sets, and per node its
public record and its proof. It never receives an entry secret, a node's
private key or application data, so it cannot store them.

**The entry secret proof.** Each set has an entry secret, 32 random bytes
made by the set's first node (`keel cloud entry-secret`) and given by the
operator to every node that joins. A node proves it holds the secret with
an HMAC-SHA256, keyed with it, over its whole record; the service stores
and relays the proof
and cannot make one, for its own key or for a changed endpoint or address.
Every node checks every record of its set against the secret before it
admits it (`keel_cloud/node/pins.py`).

**Two keys, two scopes.** The enrollment key a node holds can register
and read; it cannot confirm a peer, change a set or make a key, so a key
read off a node does not admit anything.

**The operator confirms new peers.** A new node is `pending` until the
operator confirms it with the account key, on the instance (`keel-cloud
peer confirm`) or from anywhere (`keel cloud confirm KEY
--account-key-file FILE`). A node admits a peer only when it is confirmed
**and** its proof verifies.

**Peers are pinned per set, on each node.** Once admitted, a peer's key
and overlay addresses are kept in `/var/lib/keel-cloud-node/pins.json`
(root, 0600). Keel Cloud can then bring a newer endpoint for a pinned key,
with a valid proof, and nothing else: it cannot replace the key, change
its addresses, roll its record back, or remove it. A new key for a known
node is a new peer, held like any other. The service keeps the same rules
on its side: a registered key keeps its addresses, and two nodes of a set
never share one.

**What a compromised Keel Cloud can and cannot do.** It can only propose:
it can withhold updates, show records to the operator that are not real,
or mark a node confirmed, but any record it made or changed fails the
proof on every node and is not admitted. It cannot add a peer to a set
without the entry secret, cannot change a pinned peer's key or addresses,
cannot read traffic between nodes (WireGuard), and cannot reach into a
node: the agent only calls out. The confirmation step guards against a
leaked entry secret together with a leaked enrollment key; a compromised
service could skip it, which is why the proof, checked on the nodes, is
the line that holds.

**The node writes only its own spec.** The agent writes the admitted
peers into `network.overlay.wireguard.peers` of this node's
`/etc/keel/instance.yaml`, after `keel spec validate` accepts the new file,
and keeps every peer the operator declared by hand. It never writes
WireGuard's configuration: `keel spec apply --system` converges the spec
and brings the overlay up under the confirmation window of decision 0018,
and `keel network confirm` keeps it.

## A node in a set

The spec's `cloud` section (keel 0.16.0, docs/spec.md "cloud" in keel):

```yaml
cloud:
  endpoint: https://cloud.example.org:8443
  api_key:
    file: /etc/keel/secrets/cloud_api_key          # the enrollment key, 0600
  entry_secret:
    file: /etc/keel/secrets/cloud_entry_secret     # the set's secret, 0600
  set: shop
  ca_file: /etc/keel/cloud-ca.pem                  # only for a self-signed instance
```

The node also declares its own side of the overlay,
`network.overlay.wireguard` with its `address`, as for any Keel overlay.
Then:

```
keel cloud entry-secret            # first node only: makes and prints the secret
keel cloud enroll                  # register this node
keel cloud sync                    # held until the operator confirms
keel cloud confirm KEY --account-key-file FILE    # the operator, once per new node
keel cloud sync                    # the confirmed peers go into the spec
keel spec apply --system           # converge the overlay, under its window
keel network confirm               # keep it
```

`systemctl enable --now keel-cloud-node` does the enroll and sync for good,
with long polling; the apply and the confirmation stay the operator's.

## TLS

The service has no plain HTTP listener. At installation the package makes
a **self-signed certificate for development** in `/etc/keel-cloud/tls/`
(an ECDSA P-256 key, `root:keel-cloud` 0640), for the machine's name; to
make one that also names the addresses nodes use:

```
/usr/libexec/keel-cloud-api/make-dev-certificate cloud.example.org 2001:db8::10
systemctl restart keel-cloud-api
```

Nodes then trust it through `cloud.ca_file`.

**A certificate from ACME, later.** For an instance on the Internet,
`certificate` and `private_key` in `/etc/keel-cloud/api.conf` point at a
certificate an ACME client keeps current, and a renewal hook restarts
`keel-cloud-api`; nodes then leave `cloud.ca_file` out. 0046 has Keel
Cloud behind Keel Web, with certificates issued by DNS-01 through its own
Keel DNS, so port 80 is never needed; that arrives with Phase B and the
high availability work, and is not built here.

## Tests

```
apt install python3-aiohttp python3-yaml python3-pytest \
    python3-pytest-aiohttp python3-pytest-cov openssl
python3 -m pytest --cov
```

The gate is 95 percent of lines and branches (`pyproject.toml`); the
suite runs the agent against the real service over TLS on `[::1]`, with
only the machine (keel and ip) faked. CI runs only through the reusable
workflow `lxc-trixie.yml` of Keel-Linux/.github, in a Debian trixie system
container on the self-hosted runner:

| Check | Workflow | What it runs |
| --- | --- | --- |
| `coverage / trixie` | `.github/workflows/tests.yml` | the suite and the coverage gate |
| `build / trixie` | `.github/workflows/packages.yml` | `dpkg-buildpackage`, `lintian` failing on any warning, and `tests/package-smoke.sh`: the service installed, running as `keel-cloud` on `[::]:8443`, TLS only, keys stored as hashes |

## The real test

On 2026-10-02, on the test VM, three LXC containers made from the Keel
Core image (step 8): `kc-api` with `keel-cloud-api`, and `kc-a` and `kc-b`
with keel 0.16.0 and `keel-overlay-cloud`, each node given only the
enrollment key, the set's entry secret and the instance's certificate.

- The service ran as `keel-cloud`, listening on `[::]:8443`; plain HTTP
  got no answer; the database held no key in plain text.
- Both nodes enrolled and were held as pending; each refused the other
  until the operator confirmed it. A node's enrollment key was refused
  (403) when it tried to confirm.
- The operator confirmed one node with `keel-cloud peer confirm` and the
  other with `keel cloud confirm` and the account key; each node's spec
  then gained the other as its only peer, with its endpoint, its `/128`
  and a keepalive.
- `keel spec apply --system` brought `wg0` up on each node under the
  window, `keel network confirm` kept it and enabled `wg-quick@wg0`, both
  nodes had a handshake, and each pinged the other over the overlay;
  `keel diff` showed every overlay field `same`.
- A compromised service was simulated by editing its database: it moved
  one node's endpoint and added a bogus peer marked confirmed. The other
  node refused both, since neither proof verified, left its spec
  unchanged and kept the overlay up; the real node's next registration
  was accepted again.
- `keel-cloud-node.service` ran on a node under its hardening, enrolled,
  and was woken by a change on the other node through its long poll, on
  an outbound connection only.

The containers were destroyed afterwards.

## Not in Phase A

- DNS with a health check (Phase B) and the registry view (Phase C).
- An overlay manifest for `cloud` and its installation screen (0046: state
  `ask` in every mode), and carrying the entry secret through the first
  boot screens; today the operator writes the two secret files.
- The shared secrets of 0041 over the tunnel, and a third node with a
  wrong entry secret refused, which are part of 0046's criterion for
  Phase A on built images; the unit tests cover the refusal.
- High availability: Keel Cloud on three sites with etcd (0046), instead
  of SQLite on one machine.

## License

GPL-3.0, see LICENSE.
