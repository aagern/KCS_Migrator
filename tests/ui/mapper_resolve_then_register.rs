//! A target ID from `resolve` cannot be held across a `register` call:
//! `resolve` borrows the mapper shared, `register` borrows it mutably, and
//! the two cannot overlap.
//!
//! This is the shape the importer would naturally fall into while rewriting
//! one policy's foreign keys and registering the next resource's IDs in the
//! same loop. `importer::rewrite_runtime_profile_match_blocks` calls
//! `.to_string()` on the resolved value precisely to end this borrow.

use kcs_migrator::id_mapper::IdMapper;

fn main() {
    let mut mapper = IdMapper::new();
    mapper.register("runtime-profile", "src-001", "tgt-999");

    let held = mapper.resolve("runtime-profile", "src-001").unwrap();

    // Still holding a shared borrow of `mapper` here.
    mapper.register("runtime-profile", "src-002", "tgt-998");

    println!("{held}");
}
