# golang.org/x/net/http2 accepts illegal `te` header values

**Affected:** `golang.org/x/net/http2` (Go 1.23 / 1.24). Confirmed via Traefik v3.x.  
**CWE:** CWE-20

RFC 9113 §8.2.2: if `te` is present in an HTTP/2 request, it MUST be exactly `"trailers"`. Any other value is malformed and MUST produce `RST_STREAM` / `PROTOCOL_ERROR`.

`x/net/http2` allows `te` (unlike `connection` / `upgrade`) but never checks the value. `te: chunked` and `te: trailers, chunked` are accepted and the handler runs.

Go issue #14214 (Go 1.7) added connection-header checks; the `te` value check was left out.

**Impact:** spec-mandated H2 rejection is missing. Traefik currently strips `te` on H2→H1, so this is not a working smuggling path today. If the header is ever forwarded, `te: chunked` is the same class as CVE-2025-4600.

## Reproduce

```
:method = POST
:scheme = https
:path = /test
:authority = target
content-length = 4
te = chunked
```

Then a 4-byte DATA frame with `END_STREAM`.

**Actual:** normal response. No `RST_STREAM`.  
**Expected:** `RST_STREAM` (`PROTOCOL_ERROR`), handler not invoked.

See `poc.py`.

## Fix

When `te` is present, accept only `"trailers"` (case-insensitive, OWS trimmed). Otherwise reject the stream with `PROTOCOL_ERROR`.

## References

- RFC 9113 §8.2.2, §8.1.1
- https://github.com/golang/go/issues/14214
- CVE-2025-4600
- https://github.com/APEvul-cyber/HTTP2_traefik_vul/tree/main/HEADERS_te_response