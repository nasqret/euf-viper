// Standalone Rust EUF quotient sanity artifact.
// Compile with: rustc artifacts/rust/euf_quotient.rs -o /tmp/euf_quotient

fn find(parent: &mut [usize], x: usize) -> usize {
    if parent[x] != x {
        let root = find(parent, parent[x]);
        parent[x] = root;
    }
    parent[x]
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let ra = find(parent, a);
    let rb = find(parent, b);
    if ra != rb {
        parent[rb] = ra;
    }
}

fn main() {
    let mut parent: Vec<usize> = (0..6).collect();
    union(&mut parent, 0, 1);
    union(&mut parent, 2, 3);
    assert_eq!(find(&mut parent, 0), find(&mut parent, 1));
    assert_eq!(find(&mut parent, 2), find(&mut parent, 3));
    assert_ne!(find(&mut parent, 0), find(&mut parent, 2));
    println!("rust-euf-quotient-ok");
}
