# T11 v6 evidence-boundary audit

Date: 2026-08-03

Status: target-free repair and qualification. The frozen target remains unopened.

## Independent findings

Two independent reviews returned NO-GO for the previous launch boundary. The
blocking defects were reproducible:

1. The launch producer sorted JSON keys while the validator required Rust field
   order, so no produced manifest could pass the real validator.
2. The default authorization polling window was about 60 seconds despite a
   one-hour compute allocation.
3. The immutable submission omitted the authorization-request executor hash.
4. The real authorizer emitted a summary receipt while the request executor
   expected the complete authorization bytes.
5. Submit-host controls inherited ambient loader, Git, Python, and Slurm
   variables.
6. Preparation claimed reproducibility while retaining only digests of the two
   builds and their streams.
7. Runtime inventories could exceed the executor's 128-file bound, and metadata
   overstated path retention as complete runtime supervision.

## Implemented repairs

- Launch schema `euf-viper.t11-stage0a-launch.v6` preserves the exact validator
  field order and is validated before no-replace publication.
- Submission schema `euf-viper.t11-stage0a-submission.v3` binds the request
  executor in the exact control-hash set used by submission, finalization, and
  authorization.
- Authorization-request schema `v3` validates its submission identity, control
  hashes, nonce, paths, scheduler identity, and full authorization payload. The
  executor recomputes the authorization ID and checks the published decision,
  submission, and scheduler-candidate bytes.
- The default finalizer poll envelope is 17,280 attempts at five seconds (24
  hours), and remains explicitly overrideable and recorded.
- Pinned controls execute under a fixed minimal environment. Fault-injection
  tests use files rather than inherited test variables; a poison-environment
  regression covers Git, loader, Python, and Slurm variables.
- Prebuilt preparation schema `v2` retains both independent ELF builds and all
  four build streams as mode-0400 artifacts. The validator byte-compares both
  builds with the published candidate and cross-checks every retained stream
  against the build report.
- Preparation and validation enforce the executor's exact 1..128 loader-file
  inventory bound.
- Metadata now says loader-closure paths are inventoried, retained, and
  revalidated. It explicitly records that dynamic-loader objects are not
  descriptor-bound.

## Trust boundary

The evidence model trusts the Linux kernel, Slurm control plane, cluster
administrator, and root-owned system runtime. It detects ordinary artifact,
checkout, scheduler-record, and same-path mutation covered by its pre/post
bindings. It does not defend against a malicious administrator, kernel, or a
concurrent identity able to rewrite trusted system loaders or the Slurm control
plane.

The Python inventory is the startup ELF loader closure, not the complete set of
standard-library source, bytecode, extension modules, locale/NSS data, or late
`dlopen` inputs. Candidate and Python runtime paths are retained and revalidated,
but the kernel loader does not consume those retained descriptors. These are
recorded limitations, not certificate claims.

## Promotion gate

No T11 scientific result may be interpreted until all of the following refer
to one clean committed revision:

1. local campaign-contract and Rust matrices pass;
2. Linux sealed-execution matrix passes on WMI;
3. the exact revision is built twice into retained byte-identical ELF artifacts;
4. the real launch producer passes the real `v6` validator;
5. an independent target-free review returns GO;
6. only then may Stage 0A open the frozen target.
