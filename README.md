# Elliptic Curve VRF

This library provides flexible and efficient implementations of Verifiable
Random Functions with Additional Data (VRF-AD), a cryptographic construct
that augments a standard VRF scheme by incorporating auxiliary information
into its signature.

It leverages the [Arkworks](https://github.com/arkworks-rs) framework and
supports customization of scheme parameters.

### Supported VRFs

- **IETF VRF**: Complies with ECVRF described in [RFC9381](https://datatracker.ietf.org/doc/rfc9381).
- **Pedersen VRF**: Described in [BCHSV23](https://eprint.iacr.org/2023/002).
- **Ring VRF**: A zero-knowledge-based inspired by [BCHSV23](https://eprint.iacr.org/2023/002).

### Schemes Specifications

- [VRF Schemes Details](https://github.com/davxy/bandersnatch-vrfs-spec)
- [Ring VRF ZK Proof](https://github.com/davxy/ring-proof-spec)

### Built-In suites

The library conditionally includes the following pre-configured suites (see features section):

- **Ed25519-SHA-512-TAI**: Supports IETF and Pedersen VRFs.
- **Secp256r1-SHA-256-TAI**: Supports IETF and Pedersen VRFs.
- **Bandersnatch** (_Edwards curve on BLS12-381_): Supports IETF, Pedersen, and Ring VRFs.
- **JubJub** (_Edwards curve on BLS12-381_): Supports IETF, Pedersen, and Ring VRFs.
- **Baby-JubJub** (_Edwards curve on BN254_): Supports IETF, Pedersen, and Ring VRFs.

### Basic Usage

```rust
use ark_ec_vrfs::suites::bandersnatch::*;
let secret = Secret::from_seed(b"example seed");
let public = secret.public();
let input = Input::new(b"example input");
let output = secret.output(input);
let aux_data = b"optional aux data";
```
#### IETF-VRF

_Prove_
```rust
use ark_ec_vrfs::ietf::Prover;
let proof = secret.prove(input, output, aux_data);
```

_Verify_
```rust
use ark_ec_vrfs::ietf::Verifier;
let result = public.verify(input, output, aux_data, &proof);
```

#### Ring-VRF

_Ring construction_
```rust
const RING_SIZE: usize = 100;
let prover_key_index = 3;
// Construct an example ring with dummy keys
let mut ring = (0..RING_SIZE).map(|i| Secret::from_seed(&i.to_le_bytes()).public().0).collect();
// Patch the ring with the public key of the prover
ring[prover_key_index] = public.0;
// Any key can be replaced with the padding point
ring[0] = RingProofParams::padding_point();
```

_Ring parameters construction_
```rust
let params = RingProofParams::from_seed(RING_SIZE, b"example seed");
```

_Prove_
```rust
use ark_ec_vrfs::ring::Prover;
let prover_key = params.prover_key(&ring);
let prover = params.prover(prover_key, prover_key_index);
let proof = secret.prove(input, output, aux_data, &prover);
```

_Verify_
```rust
use ark_ec_vrfs::ring::Verifier;
let verifier_key = params.verifier_key(&ring);
let verifier = params.verifier(verifier_key);
let result = Public::verify(input, output, aux_data, &proof, &verifier);
```

_Verifier key from commitment_
```rust
let ring_commitment = params.verifier_key().commitment();
let verifier_key = params.verifier_key_from_commitment(ring_commitment);
```

## Features

- `default`: `std`
- `full`: Enables all features listed below except `secret-split`, `parallel`, `asm`, `rfc-6979`, `test-vectors`.
- `secret-split`: Point scalar multiplication with secret split. Secret scalar is split into the sum
   of two scalars, which randomly mutate but retain the same sum. Incurs 2x penalty in some internal
   sensible scalar multiplications, but provides side channel defenses.
- `ring`: Ring-VRF for the curves supporting it.
- `rfc-6979`: Support for nonce generation according to RFC-9381 section 5.4.2.1.
- `test-vectors`: Deterministic ring-vrf proof. Useful for reproducible test vectors generation.

### Curves

- `ed25519`
- `jubjub`
- `bandersnatch`
- `baby-jubjub`
- `secp256r1`

### Arkworks optimizations

- `parallel`: Parallel execution where worth using `rayon`.
- `asm`: Assembly implementation of some low level operations.

## License

Distributed under the [MIT License](./LICENSE).
