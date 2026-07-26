# Fixed Helios campaign 19961244

This directory is the portable evidence archive for run
`20260726T230513Z-b32e204e6fe5-b5f78fb6`.

- Preparation job: `19961039` (`COMPLETED`, exit `0:0`)
- Array job: `19961244` (`COMPLETED`, 64/64 tasks, exit `0:0`)
- Finalizer job: `19961245` (`COMPLETED`, exit `0:0`)
- Orchestration revision: `b32e204e6fe525e033baab7c363b8645caa36f02`
- Candidate revision: `b5f78fb6cfef648178089a680bf365ff4367b075`
- Candidate binary SHA-256:
  `6137acfaee46cf13b828a3bb356b39e9a0420df797a94e2188490b48edba01fd`
- Audited rows: 45,018/45,018 (7,503 sources by six solver configurations)
- Portable audit SHA-256:
  `c0bfd9f526063c74e9cfce18d0874043c321244275927c25f1864489bd7f7728`
- Analysis SHA-256:
  `741dd531fa1048cb9f949a91f3db70bd8c8ef004bda3130b11f416a19393599c`

The candidate binary is retained at `preparation/target/release/euf-viper` so
the local replay can verify its receipt without Cargo state. The portable
replay reproduced the remote audit byte-for-byte.

The result is a rejected overall promotion: Viper solves 7,458 cases, 32 fewer
than Yices2. It leads Z3 default by 11 solves and ties Z3 `sat.euf=true` in
coverage, but it does not meet the all-comparator speed gate.
