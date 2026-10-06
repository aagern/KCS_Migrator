//! `resolve` hands back a borrow of the mapper, so the mapper has to
//! outlive the answer. Returning it from a function that owns the mapper
//! must not compile.

use kcs_migrator::id_mapper::IdMapper;

fn target_id_for(source: &str) -> &'static str {
    let mut mapper = IdMapper::new();
    mapper.register("runtime-profile", source, "tgt-999");
    // `mapper` is dropped at the closing brace, taking the `String` this
    // `&str` points into with it.
    mapper.resolve("runtime-profile", source).unwrap()
}

fn main() {
    let _ = target_id_for("src-001");
}
