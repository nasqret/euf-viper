# T10 target preflight evidence

This directory preserves the no-SAT target projection that terminally rejects
T10 before its full 7,503-source census.

- Core commit: `898df6d916c313baefd3baae6e820db85e678cce`
- Target SHA-256:
  `cfe0e5e611139004e7f8a06461c4cbf3066bb604786377db1a94d40e797f3112`
- Projector exit status: `3`
- Decision: `no_closed_atom_clauses`; T10 Stage 1 and WMI are forbidden

`projection.json` is the exact newline-terminated projector output.
`metadata.json` records the immutable identities and independent audit counts.
This is a selected-target falsification, not a complete corpus census.
