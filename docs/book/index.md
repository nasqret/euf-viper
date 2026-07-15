# euf-viper

`euf-viper` is a Rust EUF verifier and benchmark campaign scaffold.

The current implementation supports ground Boolean QF_UF through Tseitin CNF,
multiple SAT backends, eager finite-domain and congruence axioms, and a
congruence-closure model validator with lazy theory-lemma fallback.

```{admonition} Current Status
:class: warning
The exact post-fix campaign solves 7,269/7,503 at two seconds and 7,480/7,503 at
60 seconds. Z3 default solves 7,412 and 7,489; Yices2 solves 7,445 and 7,500.
Euf-viper remains faster geometrically than Z3 on common instances, but loses
coverage and aggregate time; Yices2 is faster and more complete. All completed
full and official promotion audits reject overall superiority. See
[Current Campaign](current-campaign.md) for the exact matrices and evidence
boundary.
```

The next program is the [Best-Overall Campaign](best-overall-campaign.md). It
adds the official QF_UF selection and OpenSMT, modernizes the SAT control,
closes independent proof/model gaps, and tests proof-carrying component-local
representation migration under held-out and full-corpus gates.

The opt-in [Assertion Lineage](assertion-lineage.md) layer implements the
source-exact T8 prerequisite at the typed Boolean/EUF boundary. Its 7,503-source
WMI census is preregistered but has not been submitted, so it authorizes no T8
search or solver claim.
