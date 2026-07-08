# Operations

## WMI

Run a live preflight:

```bash
bash scripts/wmi/preflight.sh
```

Submit the synthetic campaign after Rust is available on WMI:

```bash
bash scripts/wmi/sync_and_submit.sh
```

Submit the fixed QF_UF corpus campaign:

```bash
EUF_VIPER_CORPUS_LIMIT=40 \
EUF_VIPER_CORPUS_TIMEOUT=10 \
EUF_VIPER_CORPUS_SEED=euf-viper-qf-uf-wmi-20260708 \
bash scripts/wmi/sync_and_submit_corpus.sh
```

## LTS

Run CAS availability checks:

```bash
bash scripts/lts/preflight.sh
```

Run local CAS syntax/sanity checks where tools are installed:

```bash
bash scripts/lts/check_cas_local.sh
```
