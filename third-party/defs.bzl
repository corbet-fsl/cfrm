load("@prelude//rust:cargo_package.bzl", "cargo")

# reindeer emits `platform = ...` arguments, which only the prelude's cargo.* wrappers accept.
def tp_rust_library(**kwargs):
    cargo.rust_library(**kwargs)

def tp_rust_binary(**kwargs):
    cargo.rust_binary(**kwargs)
