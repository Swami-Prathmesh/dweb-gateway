# dweb-gateway

A working content-addressed gateway: the bridge an IPFS gateway provides between ordinary
HTTP and the decentralized web, built from scratch with the Python standard library.

Point a browser at it, ask for content by its identifier, and it resolves, verifies and
serves it. Report a CID as abusive and it answers `410 Gone`. Nothing is mocked: the CIDs
are real SHA-256 hashes, the verification is real, and the HTTP semantics are the ones a
public gateway actually uses.

```
python3 start.py
```

That is the whole setup: it picks a free port, starts the gateway and opens the guided
view in your browser. On Windows double-click `run.bat`; on macOS or Linux use `run.sh`.
No arguments, no dependencies, no accounts, no network access.

Requires Python 3.8+. Keep the files in one folder.

Two views are served:

- **`/` — guided view.** Plain language, three things to try, no identifiers on screen.
  For anyone who just wants to see what this is.
- **`/panel` — technical view.** CIDs, integrity state, denylist, tamper and repair.
  For anyone who wants to take it apart.

---

## What it does

| Concern | Implementation |
| --- | --- |
| Identifier | CIDv1: version `1`, raw codec `0x55`, sha2-256 multihash `0x12 0x20`, base32 multibase with `b` prefix |
| Addressing | Hash of the content, so the same bytes always produce the same CID |
| Resolution | `/ipfs/<cid>/<path>` walks directory link manifests to the requested block |
| Integrity | Every block is re-hashed before serving; a mismatch is refused with `502` |
| Retrieval | Plain HTTP `200`, plus trustless raw blocks for clients that verify themselves |
| Caching | `ETag` = CID, `Cache-Control: public, max-age=29030400, immutable`, `304` on `If-None-Match` |
| Ranges | `Range: bytes=a-b` → `206`, unsatisfiable → `416`, capped at 5 GiB like the public gateways |
| Refusal | Denylist → `410 Gone`, with the takedown receipt in the body |
| Directories | A block whose JSON body maps names to CIDs; a site is one root CID over many file CIDs |

## Endpoints

```
GET  /                                  guided view (plain language)
GET  /panel                             technical control panel
GET  /README.md                         this file
GET  /ipfs/<cid>[/<path>]               content by CID
GET  /ipfs/<cid>?format=raw             raw block bytes (application/vnd.ipld.raw)
GET  /healthz                           liveness
GET  /api/blocks                        block inventory with integrity state
GET  /api/denylist                      denylist mirror
GET  /api/stats                         counters
POST /api/publish                       {"content", "name", "content_type"} or {"links": {name: cid}}
POST /api/report                        {"cid", "reason"} -> receipt, then 410
POST /api/unblock                       {"cid"} -> restore service
POST /api/tamper                        {"cid"} -> flip a byte on disk (integrity demo)
POST /api/repair                        {"cid"} -> restore the original bytes
```

`GET /ipfs/...` also honours `Accept: application/vnd.ipld.raw` as an alternative to
`?format=raw`, and `HEAD` is supported throughout.

## A five-minute walkthrough

0. **Start guided.** Open `/` and work through the three steps: open the example site,
   publish a note, then report a page and watch it be refused. Everything the guided view
   does is a real call against the gateway.
1. **Resolve something.** In the control panel, press *get* on `hello.txt`. The status line
   shows the code, the time, and `verified sha2-256`; the body is the exact bytes.
2. **Fetch a site.** Press *get* on the directory row. `/ipfs/<root>/` resolves
   `index.html` through the manifest, and `/ipfs/<root>/style.css` resolves a second block.
   Every file keeps its own CID; the site has one root.
3. **Verify it yourself.** Tick *trustless raw* and fetch the `hello.txt` block, then hash
   what came back:
   `curl -s 'http://127.0.0.1:8787/ipfs/<hello-cid>?format=raw' | sha256sum`.
   The gateway hands over the block bytes; the check is yours. (For a directory root, use the
   trailing-slash form or add `-L` — `/ipfs/<cid>` redirects to `/ipfs/<cid>/`.)
4. **Break it.** Press *tamper* on a block, then fetch it. One byte changed on disk and the
   gateway refuses with `502` instead of serving content that no longer matches its address.
   Press *repair* to put it back.
5. **Take it down.** Press *report* on the `blocked-sample.txt` row. You get a receipt, the
   CID lands on the denylist, and the next fetch returns `410 Gone`. Try it in a private
   window or with `curl` — your browser may still have the old bytes cached, which is exactly
   the caveat the public gateways document.

Step 5 is worth reading twice: denylisting does not delete anything. It makes *this gateway*
decline to serve an identifier, which is the authority a gateway actually has.

## Layout

```
start.py           launcher: free port, starts the server, opens the browser
dweb_gateway.py    the server: CID math, block store, denylist, HTTP surface, seed content
simple.html        guided view served at / (plain language, three things to try)
webui.html         technical control panel served at /panel
test_gateway.py    end-to-end suite, 56 checks, no dependencies
run.sh / run.bat   one-line launchers for macOS-Linux and Windows
store/             created on first run: blocks/, meta/, denylist.json
```

`python3 dweb_gateway.py --reset` wipes the store and re-seeds the demo content.
`python3 start.py` is the friendlier entry point: same server, free port, browser opened for you.

## What is real, and what is not

Real: the CID encoding and hashing, content addressing, per-request verification, the
gateway path surface, trustless raw retrieval, range handling, caching headers, and the
report → review → denylist → `410` flow.

Not real: there is no libp2p, no DHT, no bitswap, no dag-pb or UnixFS, no pinning, and no
peers. Blocks live on local disk and directories are JSON link manifests rather than dag-pb
nodes. Real IPFS file CIDs use the dag-pb codec and chunk files, so `ipfs add` of the same
bytes produces a different CID than this server does. The addressing, the verification, the
HTTP surface and the takedown semantics are the parts that carry over.

## Where this maps to the real thing

The behaviour here follows the [ipfs.io public gateway](https://about.ipfs.io/) model: a
gateway is a public utility that bridges HTTP and the IPFS network, content is uploaded by
third parties and the user carries the consequences of using it, and violations may be
disabled without compensation by adding the identifier to the Bad Bits denylist. Reports go
to `abuse@ipfs.io` with the CID and the reason; copyright claims need full DMCA detail; a
confirmed takedown lands on `badbits.dwebops.pub` and gateways answer `410`.

If you want the real stack rather than this model of it:

- **Kubo** (`ipfs` CLI) to run a node, pin content and serve a gateway locally.
- **Helia** for a JavaScript IPFS implementation in the browser.
- **inbrowser.link** for a Service Worker gateway that does trustless retrieval without a
  server in the path.

## Notes before you expose it

The server binds to `127.0.0.1` on purpose: there is no authentication, no rate limiting and
no size limit worth relying on. HTML is previewed in a sandboxed frame in the panel, but
`/ipfs/<cid>` itself serves what you published, scripts included. Treat it as a local
laboratory, not a service to put on the internet. A real gateway also needs a review queue
with human judgement — here the review step is instant and unconditional, so the flow can be
demonstrated end to end.
