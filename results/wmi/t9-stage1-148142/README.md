# T9 Stage 1 WMI Result

T9 is rejected. Job `148142` completed on 2026-07-17 with the harness's
scientific-failure exit code `3`; the independent audit status is `verified`.
No broad T9 campaign is authorized.

## Exact execution

- Harness revision: `37aeefef7ad8fdcc82752c4dc71e5bce0e906223`
- Harness tree: `01372c901e964270d2f06c23d76fb9d235e694d2`
- Hosted Linux gate: GitHub Actions run `29548321207`, success
- Stage 0 binary revision: `7e5f690a0f4a044c8f77e2bdfa04a82cdf1a7aca`
- Stage 0 binary SHA-256: `51f2552fd6acd40a1f9f02c28d3f578414fb309f32794c28e081c72b4037bb1c`
- Comparator: Yices 2.7.0, SHA-256
  `eab7efbff2a6f0cce2fcd2c25cb4a94e0e048c902d8ef9e6fd7d7989aa54c501`
- Node and lane: `g1n4`, `gpu_idle`, affinity `[0]`
- Schedule: 24 distinct sources, 456 observations, four balanced repeats

The default CPU partition was unavailable during cluster servicing. The
successful job used one CPU on `g1n4`; an inner Slurm step pinned the reviewed
script with `srun --cpu-bind=map_cpu:0`. Jobs `148126` and `148137` are
preserved as zero-observation preflight failures: the first rejected the wrong
compute-node Python hash, and the second rejected affinity `[0,1]`. Probes
`148135`, `148138`, and `148140` established the exact interpreter and binding
used by the replacement.

## Scientific decision

- Sole selected target converted from four `2s` baseline timeouts to four
  correct `unsat` results; candidate median was `547,702,323ns`.
- Yices2 median on the same target and node was `25,280,921ns`.
- Registered Yices speedup was `0.0456194x`; equivalently, T9 was `21.9205x`
  slower than Yices2. The required threshold was at least `1.05x`.
- Anti-target p95 overhead was `1.006033`, passing the `1.01` ceiling.
- There were zero wrong answers, execution errors, missing groups, or
  baseline-only solves.
- The all-required correctness gates also failed because eleven nonselected
  hard Goel controls timed out under the frozen two-second limit.

The result validates T9 as a narrow coverage repair but falsifies it as a
competitive route. Its eager transitivity materialization is not eligible for
sample-40, hot-400, full-corpus timing, merge, or promotion.

## Bound artifacts

- `raw.jsonl`: `516595fb620169b83993927859a59d75886b564819d62fec9588eed13e3c8ea2`
- `summary.json`: `e9d11fc73cf9b9700c33ec0777e917892e95fde987c10bb388f1810e01e3b1a7`
- `audit-receipt.json`: `c7591dfd4726d9e0745c82ff47548bb265cdf72ca52fe859411e914a7b0b996b`
- `metadata.json`: `74dbbec0132e9a08ef6c45f0fc4a758a69df9a49df13d77293eafc3231a487bf`

`summary.json` and `audit-receipt.json` are authoritative. `slurm-receipt.json`
records scheduler provenance and the fail-closed preflight lineage.
