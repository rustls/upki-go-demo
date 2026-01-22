# upki demo with Go

This is a minimal demonstration of how upki can be integrated into a Go application.

Note: on macOS (and presumably Windows), Go uses the platform verifier which has revocation
context. To demo properly, run on an OS where Go uses its own verifier, like Linux.

## Preparation

- Checkout the [high-level revocation API](https://github.com/rustls/upki/pull/21) branch
- `cargo install --path upki`
- `upki fetch`
- Clone this repository

## Preview

```sh
enrai-2024 upki upki-go-demo $ go run main.go https://example.com
Certificate chain has 2 verified chain(s)
Chain 0:
  [0] example.com
  [1] Cloudflare TLS Issuing ECC CA 3
  [2] SSL.com TLS Transit ECC CA R2
  [3] SSL.com TLS ECC Root CA 2022
Chain 1:
  [0] example.com
  [1] Cloudflare TLS Issuing ECC CA 3
  [2] SSL.com TLS Transit ECC CA R2
  [3] SSL.com TLS ECC Root CA 2022
  [4] AAA Certificate Services

NotRevoked
<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.<p><a href="https://iana.org/domains/example">Learn more</a></div></body></html>
enrai-2024 upki upki-go-demo $ go run main.go https://evssldemo4.twca.com.tw/
Certificate chain has 2 verified chain(s)
Chain 0:
  [0] evssldemo4.twca.com.tw
  [1] TWCA Global EVSSL Certification Authority
  [2] TWCA Global Root CA
Chain 1:
  [0] evssldemo4.twca.com.tw
  [1] TWCA Global EVSSL Certification Authority
  [2] TWCA Global Root CA
  [3] TWCA Root Certification Authority

CertainlyRevoked
Get "https://evssldemo4.twca.com.tw/": upki revocation-check failed with exit code 2
exit status 1
```
