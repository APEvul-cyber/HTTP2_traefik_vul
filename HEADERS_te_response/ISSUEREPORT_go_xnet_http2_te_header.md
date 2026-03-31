# x/net/http2: server accepts `te` header with values other than "trailers" in HTTP/2 requests

## Summary

The HTTP/2 server in `x/net/http2` accepts requests containing `te` header values other than `"trailers"` (e.g., `te: chunked`, `te: trailers, chunked`) without treating the message as malformed.

RFC 9113 §8.2.2 requires:
> The TE header field [...] MAY be present in an HTTP/2 request; when it is, it MUST NOT contain any value other than "trailers".

Violation must result in a PROTOCOL_ERROR stream error (§8.1.1).

The current code correctly allows `te` as a special-case header in HTTP/2 (unlike `connection`, `upgrade`, etc. which are fully rejected), but does not check the **value** against the `"trailers"`-only constraint.

## Reproduction

Send an HTTP/2 request to any Go HTTP/2 server with:

```
:method = POST
:scheme = https
:path = /test
:authority = localhost
content-length = 4
te = chunked
```

### Actual Result

Request is accepted. Application handler is invoked normally.

### Expected Result

Stream is rejected with RST_STREAM (PROTOCOL_ERROR). Application handler is not invoked.

## Investigation

Issue #14214 (`x/net/http2: validate connection headers more`, resolved Go 1.7) addressed connection-specific header rejection. The `te` header was correctly special-cased to be **allowed** (since RFC permits `te: trailers`), but the **value** was never validated against the `"trailers"`-only requirement.

## Downstream Impact

This affects all Go-based HTTP/2 servers. Confirmed on **Traefik** (v3.x) and **Caddy** (v2.x), both of which accept illegal `te` values in HTTP/2 requests. HAProxy (C implementation) correctly rejects the same requests with PROTOCOL_ERROR.

## Security Context

The `te` header is typically stripped during H2→H1 translation, which mitigates the immediate forwarding risk. However, the H2-layer acceptance violates the specification's defense-in-depth design. If the illegal `te` value reaches an HTTP/1.1 backend through any path, it could enable TE-based request smuggling (same class as CVE-2025-4600, Google Cloud LB TE.0 smuggling).

## Suggested Fix

In the HTTP/2 server header validation path, when `te` is encountered:

1. Check that the value equals `"trailers"` (case-insensitive, after trimming OWS per RFC 9110)
2. If not, treat the stream as malformed and send RST_STREAM with PROTOCOL_ERROR

## References

- RFC 9113 §8.2.2 — TE constraints in HTTP/2
- RFC 9113 §8.1.1 — Malformed message handling
- #14214 — Original connection header validation (Go 1.7)
