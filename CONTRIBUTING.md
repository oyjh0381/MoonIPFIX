# Contributing

MoonIPFIX implementation work is tracked in GitHub Issues. Select an issue labelled `ready-for-agent`, verify its dependencies, and keep the change scoped to the externally observable behavior described by that issue.

Before submitting changes, run:

```sh
moon fmt --check
moon check --target all --deny-warn
moon test --target wasm-gc --deny-warn
moon test --target js --deny-warn
moon test --target native --deny-warn
moon info
git diff --exit-code
```

Tests should enter through the `decoder`, `registry`, or `jsonl` Interfaces, or through the Native CLI. Do not expose wire-reader, Template Store, buffering, or recovery implementation details solely for tests.

Protocol changes must cite the controlling RFC section or IANA registry revision. New fixtures must state their source and redistribution terms; synthetic fixtures are preferred.
