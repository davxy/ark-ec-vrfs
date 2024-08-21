# Elliptic Curve VRFs

Provides:
- IETF VRF as described by [RFC 9381](https://datatracker.ietf.org/doc/rfc9381).
- Pedersen VRF as described by the first construction in [Burdges et al.](https://eprint.iacr.org/2023/002).
- Ring VRF as briefly described in [Vasilyev et al.](https://eprint.iacr.org/2023/002) and further elaborated [here](https://github.com/davxy/ring-proof-spec).

A formal yet quite lightweight specification of the schemes provided can be found [here](https://github.com/davxy/bandersnatch-vrfs-spec).

The implementation is built leveraging [Arkworks](https://github.com/arkworks-rs) libraries
and is designed to be flexible for further customization.
