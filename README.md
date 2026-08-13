# HTTP2_traefik_vul

PoC and reports for Traefik / `golang.org/x/net/http2`.

| Dir | Issue |
|---|---|
| `HEADERS_te_response` | HTTP/2 accepts `te` values other than `trailers` (RFC 9113 §8.2.2) |