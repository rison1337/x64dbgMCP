## What this changes

<!-- Brief summary of the change and the motivation. -->

## Type
- [ ] Bug fix
- [ ] New tool / capability
- [ ] Docs
- [ ] Build / CI / chore

## Checklist
- [ ] `python -m unittest discover -s tests -v` passes
- [ ] New/changed MCP tools return a structured `{ "ok": ... }` payload and have a
      clear docstring (Parameters / Returns)
- [ ] If the C++ plugin changed, it builds for both arches
      (`cmake --build build --target all_plugins`)
- [ ] Docs/README updated if behaviour or setup changed
- [ ] Commit messages follow Conventional Commits
