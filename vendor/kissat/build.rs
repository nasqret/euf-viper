extern crate cc;

use std::fs;

pub fn main() {
    let excluded = [
        "application.c",
        "build.c",
        "handle.c",
        "main.c",
        "parse.c",
        "witness.c",
    ];
    let files = fs::read_dir("kissat/src")
        .expect("Cannot find 'kissat' directory")
        .filter_map(Result::ok)
        .filter(|p| {
            let name = p.file_name().to_string_lossy().into_owned();
            name.ends_with(".c") && !excluded.contains(&name.as_str())
        })
        .map(|p| p.path())
        .collect::<Vec<_>>();

    let mut build = cc::Build::new();
    build
        .define("COMPACT", None)
        .define("NDEBUG", None)
        .define("NOPTIONS", None)
        .define("NPROOFS", None)
        .define("QUIET", None);

    // CaDiCaL embeds a newer Kitten with the same global C names. Prefix the
    // legacy Kissat copy so both SAT backends can coexist in one Rust binary.
    for symbol in [
        "kitten_calloc",
        "kitten_init",
        "kitten_embedded",
        "kitten_track_antecedents",
        "kitten_shuffle",
        "kitten_clause",
        "new_learned_klause",
        "kitten_clear",
        "kitten_release",
        "kitten_solve",
        "kitten_compute_clausal_core",
        "kitten_traverse_clausal_core",
        "kitten_traverse_core_lemmas",
        "kitten_shrink_to_clausal_core",
        "kitten_value",
    ] {
        let namespaced = format!("euf_viper_{symbol}");
        build.define(symbol, Some(namespaced.as_str()));
    }

    build.files(files).compile("kissat");
}
