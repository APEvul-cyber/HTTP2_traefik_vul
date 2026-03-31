# Go x/net/http2: Illegal `te` Header Values Accepted in HTTP/2 Server Without PROTOCOL_ERROR

## Summary

Improper input validation in `golang.org/x/net/http2` allows remote attackers to send HTTP/2 requests with illegal `te` header values (e.g., `te: chunked`, `te: trailers, chunked`) to any Go-based HTTP/2 server without receiving a stream error, because the HTTP/2 server implementation does not enforce the `"trailers"`-only constraint required by RFC 9113 §8.2.2.

## Affected Software

- **Component**: `golang.org/x/net/http2` (and `net/http` HTTP/2 server)
- **Confirmed on**: Go 1.23.x / 1.24.x (latest at time of testing)
- **Downstream affected**: All Go-based HTTP/2 servers, including **Traefik** (v3.x) and **Caddy** (v2.x)
- **CWE**: CWE-20 (Improper Input Validation)

## Description

RFC 9113 §8.2.2 states:

> The TE header field [...] MAY be present in an HTTP/2 request; when it is, it MUST NOT contain any value other than "trailers".

Any HTTP/2 message with a `te` value other than `"trailers"` MUST be treated as malformed (§8.1.1), resulting in a stream error of type PROTOCOL_ERROR.

Go's `x/net/http2` server correctly identifies `te` as a special-case header that is allowed in HTTP/2 (unlike other connection-specific headers like `connection` or `upgrade`). However, it **does not validate the value** — any `te` value is accepted, including `te: chunked` and `te: trailers, chunked`.

Go issue **#14214** (2016, resolved in Go 1.7) addressed connection-specific header validation in HTTP/2, but the `te` value constraint was not included in the fix.

Comparison under identical test conditions (all configured as H2→H1 reverse proxies):

| Software | `te: trailers, chunked` | `te: chunked` | RFC 9113 Compliant |
|----------|------------------------|----------------|-------------------|
| HAProxy (C) | RST_STREAM PROTOCOL_ERROR | RST_STREAM PROTOCOL_ERROR | Yes |
| **Traefik** (Go) | **Accepted** | **Accepted** | **No** |
| **Caddy** (Go) | **Accepted** | **Accepted** | **No** |

Both Traefik and Caddy inherit this behavior from Go's `x/net/http2`.

## Impact

**Direct**: Go-based HTTP/2 servers accept requests that RFC 9113 mandates MUST be treated as malformed. The specification's H2-layer defense against connection-specific header abuse is not enforced.

**Escalated** (conditional): When Go-based proxies translate H2→H1, the `te` header is currently stripped. However, if the Go HTTP/2 server is used in a context where the header is preserved (custom middleware, non-proxy use, or future library changes), the illegal `te` value could reach HTTP/1.1 backends. `te: chunked` acted upon by a backend could enable CL/TE request smuggling — the same attack class as CVE-2025-4600 (Google Cloud LB, TE.0 smuggling).

## Proof of Concept

### Reproduction

Against any Go-based HTTP/2 server (tested via Traefik and Caddy as reverse proxies):

```python
headers = [
    (b":method", b"POST"),
    (b":scheme", b"https"),
    (b":path", b"/test"),
    (b":authority", b"target:443"),
    (b"content-length", b"4"),
    (b"te", b"chunked"),
]
```

1. Establish TLS connection with ALPN `h2`
2. Send HTTP/2 connection preface + SETTINGS
3. Send HEADERS frame with the above headers
4. Send DATA frame (4 bytes), END_STREAM set

### Observed Result

Server returns H2 HEADERS + DATA response. No RST_STREAM, no GOAWAY. HAProxy returns RST_STREAM PROTOCOL_ERROR under identical conditions.

### Expected Result

The server should treat the stream as malformed and respond with RST_STREAM (PROTOCOL_ERROR).

## Suggested Fix

In `x/net/http2` server header validation (where connection-specific headers are checked), add a value check for `te`:

1. If `te` header is present, verify the value equals `"trailers"` (case-insensitive, after trimming optional whitespace)
2. If not, reject the stream with PROTOCOL_ERROR
3. Do not pass the request to the application handler

This is consistent with the existing logic that allows `te` as a special case while rejecting other connection-specific headers.

## References

- RFC 9113 §8.2.2 — `te` header constraints in HTTP/2
- RFC 9113 §8.1.1 — Malformed message handling
- Go issue #14214 — `x/net/http2: validate connection headers more` (resolved Go 1.7, but `te` value check incomplete)
- CVE-2025-4600 — Google Cloud LB TE.0 smuggling (same attack class)
- CVE-2026-26365 — Akamai `Connection: Transfer-Encoding` smuggling
- PoC Repository — https://github.com/APEvul-cyber/HTTP2_traefik_vul/tree/main/HEADERS_te_response
