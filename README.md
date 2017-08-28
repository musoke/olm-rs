# olm-rs

The [Olm](https://git.matrix.org/git/olm) cryptographic ratchet (itself an
implementation of [The Double Ratchet
algorithm](https://whispersystems.org/docs/specifications/doubleratchet/)),
[rewritten in rust](https://transitiontech.ca/random/RIIR).

Relevant docs: 

  - [Double Ratchet](https://whispersystems.org/docs/specifications/doubleratchet/doubleratchet.pdf)
  - [Olm](https://git.matrix.org/git/olm/about/docs/olm.rst)
  - [Megolm](https://git.matrix.org/git/olm/about/docs/megolm.rst)

## Warning

__I am not a cryptographer.  Assume I know nothing about cryptography.
Furthermore, the crypto libraries I depend on make similarly pessimistic
warnings.  This is basically just for fun for now.__
I'll be happy if it just gets to a state where it can interface with the
reference implementation.
