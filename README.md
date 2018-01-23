# olm-rs

The [Olm](https://git.matrix.org/git/olm) cryptographic ratchet (itself an
implementation of [The Double Ratchet
algorithm](https://whispersystems.org/docs/specifications/doubleratchet/)),
[rewritten in rust](https://transitiontech.ca/random/RIIR).

Relevant docs: 

  - [Double Ratchet](https://whispersystems.org/docs/specifications/doubleratchet/doubleratchet.pdf)
  - [Olm](https://git.matrix.org/git/olm/about/docs/olm.rst)
  - [Megolm](https://git.matrix.org/git/olm/about/docs/megolm.rst)

  - [Unstable matrix spec](https://matrix.org/speculator/spec/drafts%2Fe2e/client_server/unstable.html#end-to-end-encryption)
  - https://matrix.to/#/!wzHrsErnsyaqbpFiRQ:matrix.org/$1481746849447546UYXxY:matrix.org
  - https://matrix.org/~matthew/2016-12-22%20Matrix%20Balancing%20Interop%20and%20Privacy.pdf

## Differences between Double Ratchet and Olm

Initialization of ratchets: Double Ratchet applies the same `KDF_RK` to the
shared secret as when advancing the root key under normal operation. Olm
applies a HKDF with a different info (`OLM_ROOT` instead of `OLM_RATCHET`).

## Todo

  - Better one-time keys: `ring` currently only has ephemeral Diffie-Hellman keys.
    These can only be used once.

    For this reason, identity keys and one-time keys are generated through
    `::generate_unrandom()`.
    This stores a random `u8` seed, which is then used to return a consistent
    private key.
    This is good enough for simple compatibility testing, but obviously
    horribly insceure for actual use.

  - Better implementation of encryption.

    `ring` does not yet have AES-CBC with HMAC-SHA256, so I've cobbled it
    together from `rust-crypto`, likely not very well.

  - Better errors.
    Currently using [failure](https://boats.gitlab.io/failure/), but not very well.
    There are a lot of `.unwraps()`.

  - Use `ruma-signatures` directly to sign json, etc.


# Warning

__I am not a cryptographer.  Assume I know nothing about cryptography.
Furthermore, the crypto libraries I depend on make similarly pessimistic
warnings.  This is basically just for fun for now.__
I'll be happy if it just gets to a state where it can interface with the
reference implementation.


