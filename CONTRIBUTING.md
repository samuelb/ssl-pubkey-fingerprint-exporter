# Contributing

Thanks for helping improve spki-fingerprint-exporter! Bug reports,
fixes, features, and documentation are all welcome.

## Quick start

```sh
git clone https://github.com/samuelb/spki-fingerprint-exporter.git
cd spki-fingerprint-exporter
make build
make test   # go vet + tests with race detector
```

You'll need Go (see `go.mod` for the minimum version).

## Making changes

1. Create a feature branch from `master`.
2. Keep your change focused — one topic per pull request.
3. Format with `gofmt`, add tests for behavioral changes, and make sure
   `make test` passes.
4. Open a pull request describing what you changed and why.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/) —
please follow that format for all commits. Write the summary in the
imperative mood ("add", not "added") and keep it under ~72 characters.

## Reporting issues

Open a GitHub issue with the exporter version, what you expected, what
happened, and steps to reproduce. For feature requests, describe the use
case — it helps more than a proposed solution.

## License

By contributing, you agree that your contributions are licensed under the
project's [LICENSE](LICENSE).

Happy hacking! 🎉
