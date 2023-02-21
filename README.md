# check\_ssl\_cert

A monitoring plugin to check remotely a TLS certificate chain.

|   |   |
|---|---|
| `-H, --host=STRING` | host to connect to |
| `-p, --port=INTEGER` | port to connect to (default: 443) |
| `-P, --capath=STRING` |  check the chain against this ca bundle (default: /etc/ssl/certs/ca-certificates.crt)|
| `-C, --warning=INTEGER` | if any of the certs in the chain expire within this number of days emit a WARNING |
| `-t, --timeout=INTEGER` | Seconds before plugin times out (default: 15) |

Exits CRITICAL if the verification fails, i. e. the chain does not go back to any
of the certificates in the bundle or a certificate in the chain has expired.

No host name verification is done.

## Bugtracker

<https://codeberg.org/data/check_ssl_cert/issues>
