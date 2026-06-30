# Dual_EC_DRBG — NIST SP 800-90A (January 2012) reconstruction

This is a clean-room C++23 reconstruction of the **withdrawn** normative
Dual_EC_DRBG mechanism from NIST SP 800-90A (January 2012), sections 10.3.1
and 10.4.1, using OpenSSL only for SHA-256 and elliptic-curve arithmetic.

It is **not** an official NIST reference implementation, a FIPS-validated
module, or suitable for real cryptographic use.

Implemented:

- Official P-256, P-384 and P-521 curves and the default `P`/`Q` points from
  Appendix A.1.
- `Hash_df` with SHA-256, including the 8-bit counter and 32-bit requested
  output-length encoding.
- Instantiate, reseed and generate state transitions.
- Official `seedlen` values: 256, 384 and 521 bits.
- Official maximum output-block lengths: 240, 368 and 504 bits.
- **Rightmost** (least-significant) output-bit extraction.
- Additional input, the extra final `s = x(sP)` state update, per-block reseed
  counting, and the `2^32`-block reseed interval.
- A self-test over all three official parameter sets.
- A separate laboratory mode demonstrating the trapdoor structure with
  deliberately related points `Q=dP`. This mode does **not** use the official
  NIST `Q`; it changes only the parameter relationship so the secret inverse is
  known and the exact NIST generator mechanics can be attacked visibly.

## Build with clang++

```bash
make CXX=clang++
```

Equivalent command:

```bash
clang++ -std=c++23 -O3 -Wall -Wextra -Wpedantic \
  dual_ec_nist2012.cpp -lcrypto -pthread -o dual_ec_nist2012
```

## Run

```bash
./dual_ec_nist2012 self-test
./dual_ec_nist2012 official 128 480
./dual_ec_nist2012 official 192 736
./dual_ec_nist2012 official 256 1008
./dual_ec_nist2012 lab-backdoor
```

The `official` command uses deterministic demonstration inputs so its output is
reproducible. Do not treat those inputs or outputs as random.

## Important distinction

The official public `P` and `Q` constants do not reveal the alleged secret
scalar relation. Predicting the official stream requires knowing that secret
relation (or solving the elliptic-curve discrete logarithm problem). The
`lab-backdoor` command therefore uses a deliberately planted and known relation
while retaining the standard's P-256 state transitions and 240-bit truncation.
