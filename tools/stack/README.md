# Optional implementation checks

`make vectors-check` compares all 162 appendix values with the required
Go and Python generators, plus patched Go 1.26.4 `crypto/tls` and
Markku-Juhani Saarinen's
[altkdf-rs](https://github.com/mjosaarinen/altkdf-rs) when installed.
Each absent optional source is reported and skipped. An installed
source's failure or disagreement fails the check. The Go stack and both
generators come from the same workspace; altkdf-rs is an independent
implementation.

`make check-stack` requires the Go stack. It runs both XOF profiles
through negotiated TLS 1.3 handshakes, captured Finished verification,
application data, resumption/ECH/HRR, and an HKDF control. It then runs
live interop: the Go client against the altkdf-rs `tls-demo` server in
both profiles, the altkdf-rs client against the Go server with matching
exporters, and a stock Go server, where a client that offers the XOF
falls back to HKDF and one that requires it fails with
handshake_failure. It compares every BoGo subtest name and result
against stock Go 1.26.4: 1318 PASS and 2207 SKIP. Missing, extra or
changed results fail.

Setup needs network access, a stock Go, a Go bootstrap tree of Go 1.24.6
or later (make.bash rejects older), Rust/Cargo, Python 3, Git, curl,
tar, shasum and patch. From the repository root:

```sh
GOROOT_BOOTSTRAP=/path/to/stock/go bash tools/stack/setup.sh
make vectors-check
make check-stack
```

Set `STOCK_GO=/path/to/stock/go/bin/go` if `go` on PATH is not stock Go.
Setup downloads and verifies Go 1.26.4, applies `go1.26.4-xof.patch`
with `patch -p1`, builds it, fetches BoGo dependencies with stock Go,
fetches and builds Rust at `altkdf-rs.rev`, and builds `stockserver/`
with stock Go. Move an existing `.stack` aside first. All downloaded
trees, caches, builds and logs stay in ignored `.stack/`. Checks use the
cached dependencies offline; setup alone needs the network.

`check-stack` needs permission to bind loopback TCP. If a sandbox blocks
this, run `make check-stack` outside it. Full Go JSON test output is
saved in `.stack/handshakes.jsonl`, `.stack/interop.jsonl` and
`.stack/bogo.jsonl`, with sibling stderr logs. For a sandbox with a
read-only default Go cache, run vectors-check with
`GOCACHE="$PWD/.stack/gocache" GOTMPDIR="$PWD/.stack/tmp"
TMPDIR="$PWD/.stack/tmp"`.
