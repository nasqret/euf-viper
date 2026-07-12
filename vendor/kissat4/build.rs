use std::fs;

fn main() {
    let excluded = [
        "application.c",
        "build.c",
        "handle.c",
        "main.c",
        "parse.c",
        "witness.c",
    ];
    let files = fs::read_dir("kissat/src")
        .expect("missing vendored Kissat 4.0.4 source")
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.ends_with(".c") && !excluded.contains(&name.as_ref())
        })
        .map(|entry| entry.path())
        .collect::<Vec<_>>();

    let mut build = cc::Build::new();
    build
        .define("COMPACT", None)
        .define("EMBEDDED", None)
        .define("NDEBUG", None)
        .define("NPROOFS", None)
        .define("QUIET", None);

    // CaDiCaL carries Kitten too. Prefix the public Kitten symbols so both
    // engines can be linked into euf-viper without global C symbol clashes.
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
        let prefixed = format!("euf_viper_kissat4_{symbol}");
        build.define(symbol, Some(prefixed.as_str()));
    }

    build.files(files).compile("kissat4");
    println!("cargo:rustc-link-lib=m");
    println!("cargo:rerun-if-changed=kissat/VERSION");
    println!("cargo:rerun-if-changed=kissat/src");
}
