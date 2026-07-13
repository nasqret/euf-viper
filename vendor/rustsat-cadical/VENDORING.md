# Vendoring provenance

This directory is based on the crates.io package `rustsat-cadical` 0.7.5:

- crates.io checksum: `36c1940036a11c1ff492fdbdad940ba100220f50a0ecabea1f2de08c18aa3a90`
- upstream repository: `https://github.com/chrjabs/rustsat`
- upstream commit recorded by the package: `457d6d7bf27998947edc45fa2200d6a5fef6c389`
- package path in that repository: `cadical`

The package already vendors the CaDiCaL sources and their MIT license under
`cppsrc/`. This fork restores upstream solver-test support omitted from the
published package and adds a scoped, conflict-only external-propagator bridge.
Project-specific changes are visible by comparing this directory with the
published package at the checksum above.
