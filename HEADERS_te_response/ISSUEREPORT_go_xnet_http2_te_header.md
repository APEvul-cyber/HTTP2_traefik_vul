# x/net/http2: accept `te` values other than "trailers"

RFC 9113 §8.2.2: HTTP/2 `te` MUST be `"trailers"` only. Other values MUST be `PROTOCOL_ERROR`.

The server special-cases `te` as allowed but does not check the value. `te: chunked` is accepted; the handler runs.

Confirmed on Traefik v3.x (uses `x/net/http2`). HAProxy rejects the same request.

`te` is stripped on H2→H1 today, so this is a spec-compliance / defense-in-depth bug, not a live smuggling path.

## Reproduce

Send HTTP/2 HEADERS with `te: chunked` plus a short DATA frame. See `poc.py`.

**Actual:** request handled.  
**Expected:** `RST_STREAM` (`PROTOCOL_ERROR`).

## Fix

Reject any `te` value other than `"trailers"`.

https://github.com/APEvul-cyber/HTTP2_traefik_vul/tree/main/HEADERS_te_response