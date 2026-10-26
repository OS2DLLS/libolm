# Security status and audit notes

## Status

**libolm is deprecated and is not being presented as production-secure by this audit.** The repository README explains the upstream deprecation rationale: libolm is implemented in C/C++ rather than memory-safe languages, has had memory-safety CVEs, and includes cryptographic primitives whose own documentation says they are not cryptographically secure and have no side-channel protection. The upstream project recommends migrating to [vodozemac](https://github.com/matrix-org/vodozemac).

This file records the security-related work and findings in the current `/data/libolm` workstream. It is not a security certification, a complete audit, or a replacement for upstream security support.

## Changes made in this workstream

### AES-CBC input-length validation

`src/crypto.cpp` now rejects zero-length and non-16-byte-aligned input in `_olm_crypto_aes_decrypt_cbc` before entering the block-decryption loop or reading the final padding byte. This prevents the function from reading before the output buffer for an empty input or processing a partial AES block as a complete block.

Regression coverage was added in `tests/test_crypto.cpp` for zero-length and one-byte ciphertext. An AddressSanitizer run before the guard reported an out-of-bounds stack read in `_olm_crypto_aes_decrypt_cbc`; after the guard, the test passes.

The same function now enforces PKCS#7 padding validity: padding must be in `1..16`, and every byte in the padding suffix must equal the padding length. Invalid padding causes the entire decrypted output buffer to be cleared before returning failure. New tests synthesize ciphertexts that decrypt to zero padding, padding length 17 in a 32-byte input, and inconsistent padding bytes. All three failed before the fix; they now pass under ASan and UBSan. `src/cipher.cpp` verifies the HMAC before calling CBC decryption, so this change is not evidence of an unauthenticated padding oracle in the public cipher adapter, nor a constant-time claim.

A public-API regression test was also added in `tests/test_pk.cpp`. It constructs an ephemeral Curve25519 key and a valid MAC for an empty ciphertext, then verifies that `olm_pk_decrypt` rejects the input. The test passes with the guard in place. This confirms that an authenticated empty ciphertext can reach the public-key decrypt path; the fixed low-level function now rejects it safely.

### Public-key decryption Base64-length validation order

`olm_pk_decrypt` now validates the fixed-size ephemeral-key and MAC lengths, then rejects a ciphertext Base64 length that cannot decode, before comparing plaintext capacity with the maximum plaintext length. Before this change, a one-character ciphertext made `decode_base64_length` return `size_t(-1)`; the earlier capacity check reported `OLM_OUTPUT_BUFFER_TOO_SMALL` instead of `OLM_INVALID_BASE64`. The new public-API test in `tests/test_pk.cpp` confirms the error code and that the output and input ciphertext remain unchanged. This is a focused malformed-length regression test, not evidence that all historical CVE cases or other memory-safety paths are closed. An independent review of this ordering change is pending.

### Undefined shifts found by UBSan

UBSan identified undefined signed shifts in SHA-256 word assembly, AES key-schedule word assembly and `SubWord`, Ed25519 field/scalar arithmetic and byte packing, and Curve25519 reduction, equality-mask, and byte-packing paths. The changes make byte shifts operate on unsigned `WORD`/`uint32_t` values, replace signed carry shifts with multiplication by the corresponding power of two, and use unsigned operations for Curve25519 packing and equality-mask propagation. These changes retain the existing algorithms; they do not replace or independently validate them.

### Session description length conversion

`src/session.cpp` now rejects `buflen == 0` and values above `INT_MAX` before converting the `size_t` length to `int`. The previous conversion could wrap or become implementation-defined, contrary to the function's existing comment that lengths above `INT_MAX` should be ignored. A regression test in `tests/test_session.cpp` checks the documented no-op behavior at `INT_MAX + 1`; this bound is representable and exercises the guard on both 32-bit and 64-bit `size_t` platforms. The test failed before the guard because `describe()` modified the buffer, and passes with the guard. This establishes a boundary-contract bug; it does not by itself demonstrate remote exploitability.

### Curve25519 all-zero shared-secret rejection

A differential probe found that the bundled X25519 implementation produced an all-zero shared secret for an all-zero peer public key, while OpenSSL EVP rejected the derive operation. The internal `_olm_crypto_curve25519_shared_secret` wrapper now returns a status and clears/rejects an all-zero result. Its callers in SAS, public-key encryption/decryption, Olm session setup, and ratchet chain derivation now propagate failure instead of using that secret. Public-key encryption also validates a recipient key when it is set, using a fixed, non-secret validation scalar; the temporary scalar and derived value are cleared.

Regression tests cover SAS rejection, all-zero and `u=1` low-order public-key rejection during PK recipient-key setup, PK decryption with an all-zero ephemeral key, outbound session setup with an all-zero peer key, and inbound-session rejection of both an all-zero identity key and a low-order initial ratchet key. The SAS and inbound-ratchet tests were observed failing before their respective guards; they pass afterward. Failed inbound validation now keeps the untrusted public keys in locals until all checks and shared-secret derivations succeed. A dedicated negative test for a later ratchet-chain transition is still absent.

### Verification performed

The native test suite was rebuilt after the changes above, and all 15 test executables passed under AddressSanitizer, UndefinedBehaviorSanitizer, and an optimized Release build. A separate Clang 20.1.8 ASan/UBSan build also passed all 15 test executables. The Curve25519/Ed25519 arithmetic changes were exercised by the key-generation, signing, public-key, and group-session tests. These results cover the existing test corpus only; they do not establish that every parser, API entry point, or platform is safe.

After the public-key Base64-length ordering change, all 15 Linux test executables passed under GCC ASan and GCC UBSan. After updating the `Session::describe` boundary test to use `INT_MAX + 1`, `test_session` passed under both sanitizers (3 test cases, 27 assertions). The current OS/2 build produced an LX `olm.dll`, LX `test_pk.exe` and `test_session.exe`, and an OMF test archive that `emxomfar t` could enumerate. These are cross-build/format checks only: neither test executable was run on OS/2.

### Fuzzing smoke check

The repository contains legacy AFL harnesses under `fuzzing/`, but AFL is not installed in the current environment and those harnesses were not run. A temporary libFuzzer harness for internal session unpickling was compiled outside the source tree with Clang plus ASan/UBSan. It ran for 20,000 iterations with a 4 KiB maximum input length, seeded with one valid 249-byte V2 session pickle decrypted from the existing test fixture. No crash or sanitizer finding occurred; coverage reached 104 instrumented counters. This is a short smoke campaign with a single seed, not sustained or broad fuzz coverage.

The Clang build initially exposed an invalid const-pointer declaration in `include/olm/list.hh`; the iterator over the const source list is now declared as a pointer-to-const element. This was necessary to compile the Clang build and fuzz harness, and was verified by the complete Clang test suite.

## Historical CVEs

The repository is at libolm 3.2.16. The two CVEs named in the README describe vulnerabilities in older versions, not evidence by themselves that the same bugs remain in the current checkout:

- [CVE-2021-34813](https://nvd.nist.gov/vuln/detail/CVE-2021-34813) describes a stack-based buffer overflow in `olm_pk_decrypt` affecting versions before 3.2.3. The corresponding upstream fix is present in the repository history, and the current `src/pk.cpp` validates decoded ciphertext and fixed-size key/MAC inputs before using them.
- [CVE-2021-44538](https://www.cve.org/CVERecord?id=CVE-2021-44538) describes a buffer overflow in `olm_session_describe` affecting versions before 3.2.7. The current `src/session.cpp` uses bounded `snprintf` calls and truncates the description to fit the caller's buffer.

The presence of these fixes does not demonstrate the absence of other memory-safety defects.

## Remaining security risks

### Cryptographic primitives are not suitable to accept without replacement or a separate audit

`lib/crypto-algorithms/README.md` explicitly states that its implementations are not cryptographically secure and lack resistance to side-channel attacks. In `lib/crypto-algorithms/aes.c`, key-schedule `SubWord` indexes `aes_sbox` from key bytes (lines 523–526), while `SubBytes`/`InvSubBytes` index the forward and inverse S-boxes from AES state (lines 621–656). `src/crypto.cpp` invokes this implementation for AES-CBC. These data-dependent memory accesses are a cache/timing side-channel risk on platforms where an attacker can observe memory-access timing. The protocol cipher in `src/cipher.cpp` verifies HMAC before calling CBC decryption (lines 126–138), which prevents an unauthenticated ciphertext from reaching the padding check through that adapter; it does not remove the side-channel risk for key setup or authenticated encrypt/decrypt operations. No timing/side-channel measurement was performed here.

No replacement of the AES, SHA-256, Curve25519, or Ed25519 implementations has been made as part of this work. The narrow defined-arithmetic corrections do not constitute a primitive replacement or cryptographic audit. Their algorithmic correctness, constant-time behavior, compiler output, and resistance to other side channels have not been independently established here. `src/memory.cpp`'s fixed-length `is_equal` loop is not, by itself, proof of constant-time behavior on every compiler or target.

### C and C++ memory-safety exposure remains

The CBC length check and `Session::describe()` length guard fix two narrow boundary issues; they do not remove the broader risks of parsing attacker-controlled messages, pickles, and protocol data in C/C++. The full codebase has not been audited or fuzzed exhaustively, and the existing regression tests cover only selected paths.

### Compatibility and platform validation remain open

Replacing primitives must preserve the Olm/Megolm wire formats, key derivation, MAC semantics, pickle compatibility, and existing public API behavior. Any proposed backend must also be supported on every target that libolm intends to keep, including OS/2 if that remains a requirement. No backend migration or independent cryptographic review is included here.

A target-link feasibility smoke was run for OpenSSL EVP: a small C consumer using `EVP_aes_256_cbc` and `EVP_EncryptInit_ex`/`Update`/`Final` compiled and linked against the OS/2 OpenSSL 3.6.5 target headers and OMF `libcrypto.a`; the result was recognized as an OS/2 LX executable. The link map confirms the EVP and AES symbols came from the target archive. The headers required the target pthread development files staged under the existing OpenSSL build tree. This is only a compile/link proof: it did not execute on OS/2, did not use the shared DLL at runtime, and does not establish constant-time behavior or suitability as a production backend.

Further source inspection shows why the link smoke cannot be treated as a constant-time guarantee. The OS/2 OpenSSL build compiles VPAES assembly and defines `OPENSSL_IA32_SSE2`, but `VPAES_CAPABLE` in OpenSSL 3.6.5 `crypto/aes/aes_platform.h` is gated by the SSSE3 CPUID bit. The current OS2-EMX target config does not declare SSSE3 as a minimum CPU requirement. In `crypto/evp/e_aes.c`, the AES-CBC key setup falls through to generic `AES_set_encrypt_key`/`AES_encrypt` when VPAES is unavailable; the generic implementation in `crypto/aes/aes_core.c` uses data-indexed `Te*`/`Td*` tables. Therefore the available EVP build is not established as side-channel-safe across CPUs supported by the current target. A backend decision needs either a documented/enforced CPU minimum plus runtime evidence, or a constant-time software implementation for the fallback path.

The OS/2 CMake/DLL and README work in this checkout concerns cross-build output and packaging only; it is not security hardening and does not constitute an OS/2 runtime or security verification.

## Production-readiness gate

Do not treat these changes as making libolm production-ready. Before making that claim, at minimum:

1. Select and integrate a maintained, reviewed cryptographic backend with appropriate constant-time implementations for the required platforms, or migrate consumers to the recommended successor.
2. Preserve the protocol and serialization contracts with interoperability and test-vector coverage, including negative and malformed-input cases.
3. Run the full test suite, sanitizers, and sustained fuzzing across the parser, pickle, Olm, Megolm, and public-key APIs.
4. Have the resulting implementation and threat model independently reviewed by qualified cryptography and memory-safety reviewers.
5. Verify the supported native and cross-platform builds separately; a successful build is not a runtime or security proof.

Until those gates are met, the status remains **deprecated; security work in progress; not independently re-audited or certified**.
