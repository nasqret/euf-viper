# Benchmarks

Tracked files in this directory describe benchmark ingestion.  The downloaded
corpus itself is ignored under `benchmarks/smtlib-2025/`.

## SMT-LIB 2025 QF_UF

Source: SMT-LIB release 2025, non-incremental benchmarks.

- Record: `https://zenodo.org/records/16740866`
- DOI: `10.5281/zenodo.16740866`
- File: `QF_UF.tar.zst`
- Size: `54182823`
- MD5: `e185bc80a80116bcfea116df190f87d2`
- Logic files after extraction: `7503`
- Status split after ingestion: `4361 unsat`, `3142 sat`

Commands:

```bash
scripts/bench/fetch_smtlib_qf_uf.sh
scripts/bench/sample_manifest.py benchmarks/smtlib-2025/qf_uf_manifest.jsonl \
  --limit 40 \
  --seed euf-viper-qf-uf-wmi-20260708 \
  --out benchmarks/smtlib-2025/qf_uf_sample40.jsonl
```

The manifest and sample are ignored because they contain host-local absolute
paths.  Regenerate them on each machine or cluster checkout.
