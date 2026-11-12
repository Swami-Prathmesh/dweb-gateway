import json, os, sys, threading, time, hashlib, urllib.request, urllib.error, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dweb_gateway as gw

STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".test_store")
if os.path.isdir(STORE):
    shutil.rmtree(STORE)

httpd, store, root_cid = gw.build_server(0, STORE, os.path.join(os.path.dirname(os.path.abspath(__file__)), "webui.html"))
port = httpd.server_address[1]
BASE = "http://127.0.0.1:%d" % port
threading.Thread(target=httpd.serve_forever, daemon=True).start()
time.sleep(0.4)

results = []
def req(path, method="GET", headers=None, body=None):
    url = BASE + path
    r = urllib.request.Request(url, method=method, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()

def check(name, got, want):
    ok = got == want
    results.append((ok, name, got, want))
    print(("  PASS " if ok else "  FAIL ") + name + "  -> " + str(got) + ("" if ok else " (want %s)" % want))

# 1 views
s, h, b = req("/")
check("GET / serves guided view", s, 200)
check("guided view is html", h.get("Content-Type", "").startswith("text/html"), True)
check("guided view has steps", b"Show me the example site" in b, True)
s, h, b = req("/panel")
check("GET /panel serves panel", s, 200)
check("panel has block store", b"Block store" in b, True)
s, h, b = req("/README.md")
check("GET /README.md", s, 200)
check("README is text", h.get("Content-Type", "").startswith("text/plain"), True)

# 2 blocks api
s, h, b = req("/api/blocks")
blocks = json.loads(b)["blocks"]
check("GET /api/blocks", s, 200)
check("seeded block count", len(blocks), 7)

by_name = {x["name"]: x for x in blocks}
hello = by_name["hello.txt"]["cid"]
big = by_name["big.txt"]["cid"]
site = [x for x in blocks if x["content_type"] == gw.DIR_TYPE][0]["cid"]

# 3 CID correctness
check("hello CID matches reference",
      hello, gw.cid_for(b"hello, decentralized web"))
check("hello CID has raw-sha256 prefix", hello.startswith("bafkrei"), True)

# 4 directory resolution
s, h, b = req("/ipfs/%s/" % site)
check("GET /ipfs/<root>/ -> index", s, 200)
check("index is html", h.get("Content-Type", "").startswith("text/html"), True)
check("index body correct", b == gw.DEMO_INDEX.encode(), True)
s, h, b = req("/ipfs/%s/style.css" % site)
check("GET nested link style.css", s, 200)
check("css body correct", b == gw.DEMO_CSS.encode(), True)
import http.client
conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
conn.request("GET", "/ipfs/%s" % site)
raw = conn.getresponse(); loc = raw.getheader("Location"); raw.read()
check("dir without slash redirects", raw.status, 301)
check("redirect target has slash", loc, "/ipfs/%s/" % site)
s, h, b = req("/ipfs/%s/nope.txt" % site)
check("missing link -> 404", s, 404)

# 5 plain block + headers
s, h, b = req("/ipfs/%s" % hello)
check("GET text block", s, 200)
check("body exact", b, b"hello, decentralized web")
check("verified header", h.get("X-Ipfs-Verified"), "sha2-256")
check("etag is cid", h.get("ETag"), '"%s"' % hello)
check("immutable cache", "immutable" in h.get("Cache-Control", ""), True)
check("path header", h.get("X-Ipfs-Path"), "/ipfs/%s" % hello)

# 6 conditional
s, h, b = req("/ipfs/%s" % hello, headers={"If-None-Match": '"%s"' % hello})
check("If-None-Match -> 304", s, 304)

# 7 HEAD
s, h, b = req("/ipfs/%s" % hello, method="HEAD")
check("HEAD block", s, 200)
check("HEAD content-length", h.get("Content-Length"), "24")
check("HEAD empty body", b, b"")

# 8 range
s, h, b = req("/ipfs/%s" % big, headers={"Range": "bytes=0-127"})
check("Range -> 206", s, 206)
check("Range body length", len(b), 128)
check("Content-Range present", h.get("Content-Range"), "bytes 0-127/%d" % by_name["big.txt"]["size"])
s, h, b = req("/ipfs/%s" % big, headers={"Range": "bytes=999999999-"})
check("unsatisfiable range -> 416", s, 416)

# 9 trustless raw
s, h, b = req("/ipfs/%s?format=raw" % hello)
check("raw block 200", s, 200)
check("raw content type", h.get("Content-Type"), gw.RAW_TYPE)
check("raw bytes hash to cid", gw.cid_for(b), hello)
s, h, b = req("/ipfs/%s" % hello, headers={"Accept": gw.RAW_TYPE})
check("Accept raw honoured", h.get("Content-Type"), gw.RAW_TYPE)

# 10 publish
payload = json.dumps({"content": "a brand new block", "name": "new.txt"}).encode()
s, h, b = req("/api/publish", "POST", {"Content-Type": "application/json"}, payload)
pub = json.loads(b)
check("publish -> 201", s, 201)
check("publish cid correct", pub["cid"], gw.cid_for(b"a brand new block"))
s, h, b = req("/ipfs/%s" % pub["cid"])
check("fetch published block", s, 200)
check("published body", b, b"a brand new block")
s, h, b = req("/api/publish", "POST", {"Content-Type": "application/json"},
              json.dumps({"content": "a brand new block", "name": "again.txt"}).encode())
check("same bytes -> same cid", json.loads(b)["cid"], pub["cid"])

# 11 integrity
s, h, b = req("/api/tamper", "POST", {"Content-Type": "application/json"},
              json.dumps({"cid": hello}).encode())
check("tamper ok", s, 200)
s, h, b = req("/ipfs/%s" % hello)
check("tampered block -> 502", s, 502)
check("502 explains refusal", b"does not hash to its CID" in b, True)
s, h, b = req("/api/repair", "POST", {"Content-Type": "application/json"},
              json.dumps({"cid": hello}).encode())
check("repair ok", s, 200)
s, h, b = req("/ipfs/%s" % hello)
check("repaired block -> 200", s, 200)

# 12 abuse flow
s, h, b = req("/api/report", "POST", {"Content-Type": "application/json"},
              json.dumps({"cid": hello, "reason": "test report"}).encode())
rep = json.loads(b)
check("report -> 202", s, 202)
check("receipt issued", rep["receipt"].startswith("ABUSE-"), True)
s, h, b = req("/ipfs/%s" % hello)
check("denylisted -> 410", s, 410)
check("410 names receipt", rep["receipt"].encode() in b, True)
check("410 gateway error header", h.get("X-Ipfs-Gateway-Error"), "Gone")
s, h, b = req("/ipfs/%s/" % site)
check("unrelated content still 200", s, 200)
s, h, b = req("/api/denylist")
check("denylist lists entry", hello in json.loads(b)["entries"], True)
s, h, b = req("/api/unblock", "POST", {"Content-Type": "application/json"},
              json.dumps({"cid": hello}).encode())
s, h, b = req("/ipfs/%s" % hello)
check("unblock restores 200", s, 200)

# 13 errors
s, h, b = req("/ipfs/notacid")
check("bad cid -> 400", s, 400)
s, h, b = req("/ipfs/%s" % gw.cid_for(b"never stored"))
check("unknown cid -> 404", s, 404)
s, h, b = req("/nothing/here")
check("unknown route -> 404", s, 404)
s, h, b = req("/healthz")
check("healthz", s, 200)

# 14 stats
s, h, b = req("/api/stats")
st = json.loads(b)
check("stats verified>0", st["verified"] > 0, True)

httpd.shutdown()
print("\n%d/%d passed" % (sum(1 for r in results if r[0]), len(results)))
sys.exit(0 if all(r[0] for r in results) else 1)
