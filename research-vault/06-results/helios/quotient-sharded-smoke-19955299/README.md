# Helios portable sharded smoke 19955299

This is the terminal v2 qualification of the build-once Helios runner.
Preparation job `19955162` built solver revision
`8368d21de96eec77f3bb5f6820c11d1363d3041b` once under orchestration revision
`14a46b7a5a3cd69dc238a04e2a4a74aa23b39eb3`. Array `19955299` ran two
single-core shards; dependency-gated finalizer `19955300` completed `0:0`.

The campaign has three instances, six solver configurations, and 18/18 raw
records. Viper and Yices2 solve 3/3; both Z3 configurations solve 2/3; cvc5 and
OpenSMT solve 1/3. Against Yices2, Viper records a `1.474x` PAR-2/common-total
factor and a `0.655x` common-geometric factor. The analyzer therefore rejects
promotion. This selected smoke qualifies infrastructure only.

The live analysis SHA-256 is
`9ab940b8f4a26fc06b79199491e96ebe1392178b9ee9c2d08a68a8f1b26468a8`.
The portable audit SHA-256 is
`f6e3f57079963475c2b717fcd6f29a21ace0dc625d1fd93771ddfaca24b69cb8`.
After fetching, rerunning `audit_sharded_campaign.py` reproduced the audit
byte-for-byte. The included candidate has SHA-256
`c146a7be8b2146e9d405feffc68d821608908c08d06632e738ef9ab53e9772e0`.
