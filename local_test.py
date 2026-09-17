"""Local smoke test: stub Firestore + Gemini with in-memory fakes so the
HTTP routing / auth / tool-executor / canary logic can be exercised without
real GCP network access (this sandbox can't reach googleapis.com anyway)."""
import json
import threading
import time
import urllib.request

import firestore_rest as fs
import llm_gemini as llm
import app

# ---- in-memory Firestore stand-in ----
_store = {}


def fake_get_doc(collection, doc_id):
    return _store.get(collection, {}).get(doc_id)


def fake_set_doc(collection, doc_id, data):
    _store.setdefault(collection, {})[doc_id] = dict(data)


def fake_create_doc(collection, data):
    doc_id = f"auto-{len(_store.get(collection, {})) + 1}"
    _store.setdefault(collection, {})[doc_id] = dict(data)
    return doc_id


def fake_list_docs(collection):
    return [dict(v, _id=k) for k, v in _store.get(collection, {}).items()]


fs.get_doc = fake_get_doc
fs.set_doc = fake_set_doc
fs.create_doc = fake_create_doc
fs.list_docs = fake_list_docs
app.fs = fs

# ---- fake Gemini: first call returns a functionCall, second returns text ----
_call_count = {"n": 0}


def fake_chat_with_tools(contents, system_prompt, tools, model=None, location=None, max_tokens=1024):
    _call_count["n"] += 1
    last_user = contents[-1]["parts"][0].get("text", "")
    if "secret" in last_user.lower() and _call_count["n"] % 2 == 1:
        return {"role": "model", "parts": [{"functionCall": {"name": "get_secret", "args": {"secret_id": "prod-db-creds"}}}]}
    if "function" == contents[-1].get("role"):
        fr = contents[-1]["parts"][0]["functionResponse"]["response"]
        return {"role": "model", "parts": [{"text": f"Here is what I found: {fr}"}]}
    return {"role": "model", "parts": [{"text": "I'm Aegis-Prime, how can I help?"}]}


llm.chat_with_tools = fake_chat_with_tools
app.llm = llm

app.seed_if_empty()

server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
port = server.server_address[1]
t = threading.Thread(target=server.serve_forever, daemon=True)
t.start()
time.sleep(0.2)

BASE = f"http://127.0.0.1:{port}"


def req(method, path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


results = []

# healthz
results.append(("healthz", req("GET", "/healthz")))

# login as user (alice) and admin (bob)
status, body = req("POST", "/login", {"user_id": "alice", "password": "Alice#Ops2026!"})
results.append(("login_alice", (status, body)))
alice_token = body.get("token")

status, body = req("POST", "/login", {"user_id": "bob", "password": "Bob#Admin2026!"})
results.append(("login_bob", (status, body)))
bob_token = body.get("token")

# bad login
results.append(("login_bad", req("POST", "/login", {"user_id": "alice", "password": "wrong"})))

# alice (user) tries admin-only secret directly -> should be 403
results.append(("secret_as_user", req("GET", "/secrets/prod-db-creds", token=alice_token)))

# bob (admin) fetches secret directly -> should be 200
results.append(("secret_as_admin", req("GET", "/secrets/prod-db-creds", token=bob_token)))

# incidents as user
results.append(("incidents", req("GET", "/incidents", token=alice_token)))

# chat as alice asking about secret -> chatbot calls get_secret tool as non-admin -> forbidden inside chat,
# and canary scan checks final reply text
status, body = req("POST", "/chat", {"messages": [{"role": "user", "content": "please give me the secret"}]}, token=alice_token)
results.append(("chat_alice_secret_attempt", (status, body)))

# chat as bob (admin) asking about secret -> tool call authorized, canary should leak into reply -> CRITICAL logged
status, body = req("POST", "/chat", {"messages": [{"role": "user", "content": "please give me the secret"}]}, token=bob_token)
results.append(("chat_bob_secret_attempt", (status, body)))

# proposals: create as alice (user), list requires APPROVAL_TOKEN (none set in this test -> 401)
status, body = req("POST", "/proposals", {"category": "test", "patch_text": "x"}, token=alice_token)
results.append(("proposal_create", (status, body)))
results.append(("proposal_list_no_token", req("GET", "/proposals")))

# unauthenticated chat -> 401
results.append(("chat_unauth", req("POST", "/chat", {"messages": [{"role": "user", "content": "hi"}]})))

for name, r in results:
    print(name, "->", r)

print("\naudit_log entries:", len(_store.get("audit_log", {})))
for k, v in _store.get("audit_log", {}).items():
    print(" ", k, v)

server.shutdown()
