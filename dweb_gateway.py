#!/usr/bin/env python3
"""
dweb_gateway.py - a working content-addressed gateway for the decentralized web.

This is a dependency-free reimplementation of the job an IPFS HTTP gateway does:
it takes a request for content by identifier, retrieves the bytes, verifies them
against that identifier, and serves them over plain HTTP to any browser.

What is real here
-----------------
  * CIDv1 identifiers: version 1, raw codec (0x55), sha2-256 multihash (0x12 0x20),
    base32 multibase with the 'b' prefix. Computed with SHA-256 over the bytes.
  * Content addressing: the identifier IS the hash of the content, so the same
    bytes always produce the same address, and the address cannot lie about them.
  * Verification: every block is re-hashed before it is served. A block that does
    not match its CID is refused (502) instead of being handed to the client.
  * /ipfs/<cid>/<path> resolution through directory link manifests.
  * Trustless retrieval: Accept: application/vnd.ipld.raw (or ?format=raw) returns
    the raw block bytes so the client can verify the CID itself.
  * Single-range requests (206 Partial Content / 416), HEAD, ETag, immutable
    Cache-Control headers.
  * The abuse model: an acceptable-use policy, a report endpoint that issues a
    receipt, a review step, a denylist, and 410 Gone at the gateway for anything
    denylisted - plus a note about client-side caches still holding the content.

What is deliberately not here
-----------------------------
There is no libp2p, no DHT, no bitswap, no dag-pb/UnixFS, no pinning service and
no peer-to-peer transfer. Blocks live on the local disk, and directories are JSON
link manifests rather than dag-pb nodes. Real IPFS file CIDs use the dag-pb codec
and chunk files, so a real `ipfs add` will produce a different CID for the same
bytes than this server does. The addressing, the verification, the HTTP surface
and the takedown semantics are the parts that carry over.

Run it
------
    python3 dweb_gateway.py                  # http://127.0.0.1:8787
    python3 dweb_gateway.py --port 9000
    python3 dweb_gateway.py --store ./blocks --reset

Standard library only. Python 3.8+.
"""

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import re
import secrets
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

VERSION = "0.1.0"

RAW_CODEC = 0x55
SHA2_256 = 0x12
DIR_TYPE = "application/vnd.dweb.dir+json"
RAW_TYPE = "application/vnd.ipld.raw"
CID_RE = re.compile(r"^b[a-z2-7]{20,200}$")
RANGE_LIMIT = 5 * 1024 ** 3          # mirrors the 5GiB HTTP Range ceiling on public gateways
IMMUTABLE = "public, max-age=29030400, immutable"

mimetypes.add_type("text/markdown", ".md")
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("image/svg+xml", ".svg")


# ---------------------------------------------------------------------------
# CIDv1: multibase('b') + base32(varint(version) varint(codec) multihash)
# ---------------------------------------------------------------------------

def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def _read_varint(buf, i=0):
    val, shift = 0, 0
    while True:
        if i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def _b32encode(raw):
    """RFC 4648 base32, lowercase, no padding (what multibase 'b' means)."""
    return base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def _b32decode(text):
    pad = "=" * (-len(text) % 8)
    return base64.b32decode(text.upper() + pad)


def cid_for(data):
    """CIDv1(raw, sha2-256) for a byte string."""
    digest = hashlib.sha256(data).digest()
    raw = _varint(1) + _varint(RAW_CODEC) + _varint(SHA2_256) + _varint(len(digest)) + digest
    return "b" + _b32encode(raw)


def parse_cid(cid):
    """Validate a CIDv1 and return its sha2-256 digest."""
    if not CID_RE.match(cid or ""):
        raise ValueError("not a CIDv1 base32 string")
    buf = _b32decode(cid[1:])
    version, i = _read_varint(buf, 0)
    if version != 1:
        raise ValueError("only CIDv1 is supported here")
    codec, i = _read_varint(buf, i)
    if codec != RAW_CODEC:
        raise ValueError("only the raw codec is supported here")
    mh_code, i = _read_varint(buf, i)
    if mh_code != SHA2_256:
        raise ValueError("only sha2-256 is supported here")
    length, i = _read_varint(buf, i)
    digest = buf[i:i + length]
    if len(digest) != length or length != 32:
        raise ValueError("bad multihash length")
    return digest


def verify(cid, data):
    try:
        return hashlib.sha256(data).digest() == parse_cid(cid)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Errors mapped onto HTTP status codes
# ---------------------------------------------------------------------------

class GatewayError(Exception):
    status = 500
    reason = "Internal Server Error"

    def __init__(self, detail):
        super().__init__(detail)
        self.detail = detail


class NotFound(GatewayError):
    status, reason = 404, "Not Found"


class Gone(GatewayError):
    status, reason = 410, "Gone"


class Corrupt(GatewayError):
    status, reason = 502, "Bad Gateway"


class BadRequest(GatewayError):
    status, reason = 400, "Bad Request"


class TooLarge(GatewayError):
    status, reason = 413, "Payload Too Large"


# ---------------------------------------------------------------------------
# Block store + denylist
# ---------------------------------------------------------------------------

class Store:
    """Flat content-addressed block store: one file per CID, plus a metadata sidecar."""

    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.blocks = os.path.join(self.root, "blocks")
        self.meta = os.path.join(self.root, "meta")
        self.denylist_path = os.path.join(self.root, "denylist.json")
        self.lock = threading.RLock()
        for d in (self.blocks, self.meta):
            os.makedirs(d, exist_ok=True)
        if not os.path.exists(self.denylist_path):
            self._write_json(self.denylist_path, {"entries": {}})

    # -- json helpers -------------------------------------------------------
    @staticmethod
    def _read_json(path, default):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return default

    @staticmethod
    def _write_json(path, payload):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)

    # -- blocks -------------------------------------------------------------
    def block_path(self, cid):
        return os.path.join(self.blocks, cid)

    def meta_path(self, cid):
        return os.path.join(self.meta, cid + ".json")

    def put(self, data, content_type=None, name=None):
        if isinstance(data, str):
            data = data.encode("utf-8")
        cid = cid_for(data)
        with self.lock:
            path = self.block_path(cid)
            if not os.path.exists(path):
                tmp = path + ".tmp"
                with open(tmp, "wb") as fh:
                    fh.write(data)
                os.replace(tmp, path)
            if not os.path.exists(self.meta_path(cid)):
                self._write_json(self.meta_path(cid), {
                    "content_type": content_type or mimetypes.guess_type(name or "")[0] or "application/octet-stream",
                    "name": name or cid[:12],
                    "size": len(data),
                    "created": int(time.time()),
                })
        return cid

    def get(self, cid):
        try:
            with open(self.block_path(cid), "rb") as fh:
                return fh.read()
        except FileNotFoundError:
            raise NotFound("no block stored for %s" % cid)

    def info(self, cid):
        data = self._read_json(self.meta_path(cid), {})
        data.setdefault("content_type", "application/octet-stream")
        data.setdefault("name", cid[:12])
        return data

    def has(self, cid):
        return os.path.exists(self.block_path(cid))

    def all_cids(self):
        try:
            return sorted(n for n in os.listdir(self.blocks) if not n.endswith(".tmp") and not n.endswith(".orig"))
        except OSError:
            return []

    # -- denylist -----------------------------------------------------------
    def denylist(self):
        return self._read_json(self.denylist_path, {"entries": {}}).get("entries", {})

    def is_denied(self, cid):
        return cid in self.denylist()

    def deny(self, cid, reason, receipt):
        with self.lock:
            payload = self._read_json(self.denylist_path, {"entries": {}})
            payload.setdefault("entries", {})[cid] = {
                "reason": reason,
                "receipt": receipt,
                "added": int(time.time()),
                "list": "badbits (local mirror)",
            }
            self._write_json(self.denylist_path, payload)

    def allow(self, cid):
        with self.lock:
            payload = self._read_json(self.denylist_path, {"entries": {}})
            payload.get("entries", {}).pop(cid, None)
            self._write_json(self.denylist_path, payload)

    # -- tamper demo --------------------------------------------------------
    def tamper(self, cid):
        """Flip one byte on disk so the next read fails verification."""
        path = self.block_path(cid)
        if not os.path.exists(path):
            raise NotFound("no block stored for %s" % cid)
        backup = path + ".orig"
        if not os.path.exists(backup):
            shutil.copyfile(path, backup)
        with open(path, "rb") as fh:
            data = bytearray(fh.read())
        if not data:
            raise BadRequest("cannot tamper with an empty block")
        data[len(data) // 2] ^= 0xFF
        with open(path, "wb") as fh:
            fh.write(bytes(data))
        return len(data)

    def repair(self, cid):
        path = self.block_path(cid)
        backup = path + ".orig"
        if not os.path.exists(backup):
            raise BadRequest("nothing to repair for %s" % cid)
        os.replace(backup, path)
        return True


# ---------------------------------------------------------------------------
# Resolution: /ipfs/<cid>/<path...>
# ---------------------------------------------------------------------------

def load(store, cid):
    """Fetch a block, refusing it if denylisted or if it fails CID verification."""
    if store.is_denied(cid):
        entry = store.denylist().get(cid, {})
        raise Gone(
            "This content is not available from this gateway. %s was added to the "
            "denylist (%s) after a takedown review, receipt %s."
            % (cid, entry.get("list", "badbits"), entry.get("receipt", "n/a"))
        )
    if not store.has(cid):
        raise NotFound("this gateway has no block for %s and no peers to ask" % cid)
    data = store.get(cid)
    if not verify(cid, data):
        raise Corrupt(
            "The block returned for %s does not hash to its CID, so it was refused. "
            "The bytes on disk have changed since they were addressed." % cid
        )
    return data, store.info(cid)


def resolve(store, root_cid, parts):
    """Walk a directory manifest to the requested block."""
    cur = root_cid
    for part in parts:
        if part == "":
            continue
        data, meta = load(store, cur)
        if meta.get("content_type") != DIR_TYPE:
            raise NotFound("%s is not a directory, cannot resolve /%s" % (cur, part))
        try:
            links = json.loads(data.decode("utf-8")).get("links", {})
        except ValueError:
            raise Corrupt("directory manifest %s is not valid JSON" % cur)
        if part not in links:
            raise NotFound("no link named %r in directory %s" % (part, cur))
        cur = links[part]
    data, meta = load(store, cur)
    if meta.get("content_type") == DIR_TYPE:
        links = json.loads(data.decode("utf-8")).get("links", {})
        index = "index.html" if "index.html" in links else next(
            (k for k in sorted(links) if k.endswith(".html")), None)
        if index:
            return resolve(store, links[index], [])
    return cur, data, meta


def publish_dir(store, links, name="site"):
    """Publish a JSON link manifest and return its CID."""
    manifest = {"type": "directory", "links": links}
    return store.put(json.dumps(manifest, sort_keys=True).encode("utf-8"), DIR_TYPE, name)


# ---------------------------------------------------------------------------
# Seed content: a small site, a text block, a big block, a blocked sample
# ---------------------------------------------------------------------------

DEMO_INDEX = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Served from a CID</title>
<style>
  :root { color-scheme: light dark; }
  body { margin:0; min-height:100vh; display:grid; place-items:center;
         font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
         background:#eef1f2; color:#10202b; padding:2rem; }
  @media (prefers-color-scheme: dark){ body{ background:#0b1418; color:#dfe9e7; } }
  main { max-width:46rem; }
  h1 { font-size:1.5rem; letter-spacing:-0.02em; }
  code { background:rgba(15,107,99,.12); padding:.15em .4em; border-radius:4px; }
  p { line-height:1.65; }
  a { color:#0f6b63; }
</style>
</head>
<body>
<main>
  <h1>This page has no server and no origin.</h1>
  <p>It was addressed by the hash of its own bytes and resolved through a gateway.
     Nothing here knows where the file lives &mdash; only what it must contain.</p>
  <p>Change a single character and the address changes completely. Ask for the old
     address and you get these exact bytes, or an error &mdash; never something else.</p>
  <p><code>index.html</code> and <code>style.css</code> are separate blocks, linked
     from a directory manifest that has its own CID.</p>
  <p><a href="/">&larr; back to the gateway control panel</a></p>
</main>
</body>
</html>
"""

DEMO_CSS = """/* a separate block, linked from the directory manifest */
:root { --ink: #10202b; }
"""

BLOCKED_SAMPLE = """DEMO BLOCK - takedown example
This block stands in for content that a gateway would refuse to serve after an
acceptable-use review. It contains no real material. Report it, watch the entry
land on the denylist, then fetch it again: the gateway answers 410 Gone.
"""


def seed(store):
    """Populate the store on first run. Returns the root CID of the demo site."""
    index_cid = store.put(DEMO_INDEX, "text/html; charset=utf-8", "index.html")
    css_cid = store.put(DEMO_CSS, "text/css; charset=utf-8", "style.css")
    root_cid = publish_dir(store, {"index.html": index_cid, "style.css": css_cid}, "demo-site")

    store.put("hello, decentralized web", "text/plain; charset=utf-8", "hello.txt")
    store.put(json.dumps({"name": "dweb-demo", "version": 1, "blocks": 4}, indent=2),
              "application/json", "manifest.json")
    store.put(BLOCKED_SAMPLE, "text/plain; charset=utf-8", "blocked-sample.txt")

    big = ("0123456789abcdef" * 64 + "\n") * 1024   # ~1.1 MB, for Range demos
    store.put(big, "text/plain; charset=utf-8", "big.txt")
    return root_cid


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------

STATS = {"served": 0, "blocked": 0, "verified": 0, "started": int(time.time())}


class Handler(BaseHTTPRequestHandler):
    server_version = "dweb-gateway/" + VERSION
    protocol_version = "HTTP/1.1"
    store = None
    ui_path = None

    # -- plumbing -----------------------------------------------------------
    def log_message(self, fmt, *args):
        print("  %s  %s" % (time.strftime("%H:%M:%S"), fmt % args), flush=True)

    def _send(self, status, body=b"", headers=None, content_type="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _json(self, status, payload, headers=None):
        self._send(status, json.dumps(payload, indent=2), headers, "application/json; charset=utf-8")

    def _error(self, err):
        self._send(err.status, "%d %s\n\n%s\n" % (err.status, err.reason, err.detail), {
            "X-Ipfs-Gateway-Error": err.reason.replace(" ", "-"),
        })

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 8 * 1024 * 1024:
            raise TooLarge("request body over 8 MiB")
        return self.rfile.read(length) if length else b""

    # -- routing ------------------------------------------------------------
    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self._send(204, b"", {"Allow": "GET, HEAD, OPTIONS, POST"})

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parse_qs(parsed.query)
        try:
            if path in ("/", "/index.html"):
                return self._serve_static(self.simple_path, "simple.html")
            if path == "/panel":
                return self._serve_static(self.ui_path, "webui.html")
            if path in ("/README.md", "/docs"):
                return self._serve_static(self.readme_path, "README.md",
                                          "text/plain; charset=utf-8")
            if path.startswith("/ipfs/"):
                return self._serve_ipfs(path, query)
            if path == "/healthz":
                return self._json(200, {"ok": True, "version": VERSION, "blocks": len(self.store.all_cids())})
            if path == "/api/blocks":
                return self._json(200, {"blocks": self._blocks()})
            if path == "/api/denylist":
                return self._json(200, {"entries": self.store.denylist()})
            if path == "/api/stats":
                return self._json(200, dict(STATS, version=VERSION, blocks=len(self.store.all_cids()),
                                            denylisted=len(self.store.denylist())))
            return self._error(NotFound("no route for %s" % path))
        except GatewayError as err:
            return self._error(err)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        try:
            payload = json.loads(self._body() or b"{}")
        except ValueError:
            return self._error(BadRequest("body must be JSON"))
        try:
            if path == "/api/publish":
                return self._publish(payload)
            if path == "/api/report":
                return self._report(payload)
            if path == "/api/unblock":
                cid = payload.get("cid", "")
                self.store.allow(cid)
                return self._json(200, {"ok": True, "cid": cid, "note": "removed from the local denylist mirror"})
            if path == "/api/tamper":
                cid = payload.get("cid", "")
                size = self.store.tamper(cid)
                return self._json(200, {"ok": True, "cid": cid, "bytes": size,
                                        "note": "one byte flipped on disk; the next fetch must fail verification"})
            if path == "/api/repair":
                cid = payload.get("cid", "")
                self.store.repair(cid)
                return self._json(200, {"ok": True, "cid": cid, "note": "original bytes restored"})
            return self._error(NotFound("no route for %s" % path))
        except GatewayError as err:
            return self._error(err)

    # -- handlers -----------------------------------------------------------
    def _serve_static(self, path, label, content_type="text/html; charset=utf-8"):
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except (OSError, TypeError):
            return self._send(404, "%s is missing next to the server\n" % label)
        self._send(200, body, {"Cache-Control": "no-store"}, content_type)

    def _blocks(self):
        out = []
        for cid in self.store.all_cids():
            meta = self.store.info(cid)
            entry = self.store.denylist().get(cid)
            try:
                data = self.store.get(cid)
                integrity = "ok" if verify(cid, data) else "mismatch"
            except GatewayError:
                integrity = "missing"
            out.append({
                "cid": cid,
                "name": meta.get("name"),
                "content_type": meta.get("content_type"),
                "size": meta.get("size"),
                "integrity": integrity,
                "denied": bool(entry),
                "receipt": (entry or {}).get("receipt"),
            })
        return out

    def _serve_ipfs(self, path, query):
        rest = path[len("/ipfs/"):]
        if not rest:
            raise BadRequest("expected /ipfs/<cid>/<path>")
        segments = rest.split("/")
        cid = segments[0]
        parts = segments[1:]
        try:
            parse_cid(cid)
        except ValueError as err:
            raise BadRequest("%s: %s" % (cid, err))

        # a directory requested without its trailing slash gets redirected
        if len(segments) == 1 and not path.endswith("/"):
            data, meta = load(self.store, cid)
            if meta.get("content_type") == DIR_TYPE:
                self.send_response(301)
                self.send_header("Location", path + "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        resolved_cid, data, meta = resolve(self.store, cid, parts)
        STATS["verified"] += 1

        trustless = ("raw" in [v.lower() for v in query.get("format", [])]
                     or RAW_TYPE in (self.headers.get("Accept") or ""))
        headers = {
            "ETag": '"%s"' % resolved_cid,
            "Cache-Control": IMMUTABLE,
            "X-Ipfs-Path": path,
            "X-Ipfs-Roots": resolved_cid,
            "X-Ipfs-Gateway": "dweb-gateway/" + VERSION,
            "Vary": "Accept",
            "Accept-Ranges": "bytes",
        }

        if trustless:
            # hand back the exact block bytes and let the client do its own hashing
            headers["X-Ipfs-Verified"] = "raw-block"
            return self._send(200, data, headers, RAW_TYPE)

        content_type = meta.get("content_type") or "application/octet-stream"
        if content_type == DIR_TYPE:
            content_type = "application/json; charset=utf-8"

        # conditional request
        if (self.headers.get("If-None-Match") or "").strip() == headers["ETag"]:
            STATS["served"] += 1
            self.send_response(304)
            for key in ("ETag", "Cache-Control", "X-Ipfs-Path", "X-Ipfs-Roots"):
                self.send_header(key, headers[key])
            self.end_headers()
            return

        # single byte range
        rng = self.headers.get("Range")
        if rng and content_type != DIR_TYPE:
            served = self._serve_range(data, rng, headers, content_type)
            if served:
                STATS["served"] += 1
                return

        headers["X-Ipfs-Verified"] = "sha2-256"
        STATS["served"] += 1
        self._send(200, data, headers, content_type)

    def _serve_range(self, data, rng, headers, content_type):
        match = re.match(r"^bytes=(\d*)-(\d*)$", rng.strip())
        if not match:
            return False
        total = len(data)
        if total > RANGE_LIMIT:
            return False                      # mirrors the public gateway's 5GiB ceiling
        start_s, end_s = match.groups()
        if start_s == "" and end_s == "":
            return False
        if start_s == "":
            length = min(int(end_s), total)
            start, end = total - length, total - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else total - 1
            end = min(end, total - 1)
        if start >= total or start > end:
            self.send_response(416)
            self.send_header("Content-Range", "bytes */%d" % total)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return True
        chunk = data[start:end + 1]
        out = dict(headers)
        out["Content-Range"] = "bytes %d-%d/%d" % (start, end, total)
        out["X-Ipfs-Verified"] = "sha2-256"
        self._send(206, chunk, out, content_type)
        return True

    def _publish(self, payload):
        content = payload.get("content")
        name = (payload.get("name") or "untitled").strip()[:120]
        links = payload.get("links")
        if links:
            if not isinstance(links, dict) or not all(isinstance(v, str) for v in links.values()):
                raise BadRequest("links must map name -> cid")
            for cid in links.values():
                parse_cid(cid)
            cid = publish_dir(self.store, links, name or "directory")
            kind = "directory"
        else:
            if content is None:
                raise BadRequest("provide content or links")
            if isinstance(content, (dict, list)):
                content = json.dumps(content, indent=2)
            data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
            if len(data) > 4 * 1024 * 1024:
                raise TooLarge("content over 4 MiB")
            content_type = payload.get("content_type") or mimetypes.guess_type(name)[0] \
                or "text/plain; charset=utf-8"
            cid = self.store.put(data, content_type, name)
            kind = "block"
        STATS["served"] += 1
        return self._json(201, {
            "cid": cid,
            "kind": kind,
            "gateway_path": "/ipfs/" + cid,
            "public_style_url": "http://127.0.0.1:%d/ipfs/%s" % (self.server.server_address[1], cid),
            "note": "anyone holding this CID can fetch these exact bytes from any gateway",
        })

    def _report(self, payload):
        cid = (payload.get("cid") or "").strip()
        reason = (payload.get("reason") or "not stated").strip()[:500]
        try:
            parse_cid(cid)
        except ValueError as err:
            raise BadRequest("%s: %s" % (cid, err))
        if not self.store.has(cid):
            raise NotFound("no block stored for %s, nothing to review" % cid)
        receipt = "ABUSE-%s-%s" % (time.strftime("%Y%m%d"), secrets.token_hex(3).upper())
        # a real gateway queues this for human review; the local demo reviews instantly
        self.store.deny(cid, reason, receipt)
        STATS["blocked"] += 1
        return self._json(202, {
            "receipt": receipt,
            "cid": cid,
            "status": "reviewed and denylisted",
            "policy": "acceptable use policy, ipfs.io public gateway",
            "next": "fetch it again: the gateway now answers 410 Gone",
            "client_note": ("your browser may still have the old bytes cached - "
                            "use a private window or curl to see the 410"),
        })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_server(port, store_dir, ui_path, reset=False, simple_path=None):
    if reset and os.path.isdir(store_dir):
        shutil.rmtree(store_dir)
    store = Store(store_dir)
    fresh = not store.all_cids()
    root_cid = seed(store) if fresh else None

    Handler.store = store
    Handler.ui_path = ui_path
    here = os.path.dirname(os.path.abspath(ui_path))
    Handler.simple_path = simple_path or os.path.join(here, "simple.html")
    Handler.readme_path = os.path.join(here, "README.md")
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.daemon_threads = True
    return httpd, store, root_cid


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description="A working content-addressed gateway for the decentralized web.")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--store", default=os.path.join(here, "store"))
    ap.add_argument("--ui", default=os.path.join(here, "webui.html"))
    ap.add_argument("--simple", default=os.path.join(here, "simple.html"))
    ap.add_argument("--reset", action="store_true", help="wipe the store and re-seed the demo content")
    args = ap.parse_args()

    httpd, store, root_cid = build_server(args.port, args.store, args.ui, args.reset, args.simple)
    port = httpd.server_address[1]
    base = "http://127.0.0.1:%d" % port

    print("\n  dweb-gateway %s - content-addressed gateway" % VERSION)
    print("  ------------------------------------------------")
    print("  open this    %s/        (guided view)" % base)
    print("  technical    %s/panel" % base)
    print("  blocks       %d stored, %d denylisted" % (len(store.all_cids()), len(store.denylist())))
    if root_cid:
        print("  demo site    %s/ipfs/%s/" % (base, root_cid))
    print("  store        %s" % store.root)
    print("  stop         Ctrl+C\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  stopped")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
