# Upstream provenance

- Project: Kissat
- Repository: https://github.com/arminbiere/kissat
- Release: `rel-4.0.4`
- Commit: `8af8e56f174b778aef3aa45af9f739b2a5f492c2`
- Tree: `81c120d5304b5ea5c66cc1b9bceed25e10436df9`
- License: MIT, retained in `kissat/LICENSE`

The `kissat/src` directory is an unmodified copy of that release. The Rust
wrapper compiles the library sources with `COMPACT`, `EMBEDDED`, `NDEBUG`,
`NPROOFS`, and `QUIET`; unlike the legacy SC2021 wrapper, it deliberately keeps
runtime options enabled for controlled inprocessing ablations.

Linux builds select exactly one backend:

```console
cargo build --release
cargo build --release --no-default-features \
  --features finite-symmetry,kissat-4
```

The first command is the unchanged SC2021 control. The second is the Kissat
4.0.4 candidate.
