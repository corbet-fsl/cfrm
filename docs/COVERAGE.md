# Coverage evidence

CI requires every emitted production Rust source line and branch to execute.
The shared checker validates the complete same-run LLVM JSON/LCOV file and
branch inventory, refusing missing, duplicate or malformed records. Both raw
reports and the original JSON diagnostic checker remain available. There are no
production exclusions. Native source coverage is not per-instantiation coverage
and does not replace the actual browser vectors.
