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

## Differences between Double Ratchet and Olm

Initialization of ratchets: Double Ratchet applies the same `KDF_RK` to the
shared secret as when advancing the root key under normal operation. Olm
applies a HKDF with a different info (`OLM_ROOT` instead of `OLM_RATCHET`).

# Warning

__I am not a cryptographer.  Assume I know nothing about cryptography.
Furthermore, the crypto libraries I depend on make similarly pessimistic
warnings.  This is basically just for fun for now.__
I'll be happy if it just gets to a state where it can interface with the
reference implementation.


