# Changelog

All notable changes to this project are documented in this file.

## [0.5.0] - 2026-07-13

### Bug Fixes

- Honor DEFAULT_TIMEOUT environment variable
- Use static scheme-to-port map instead of net.LookupPort
- Publish a proper multi-arch Docker manifest
- Migrate ingress to networking.k8s.io/v1
- Only tag stable releases as latest
- Default image to the upcoming v0.5.0 exporter
- Make ingress pathType configurable
- Always reserve headroom on short scrape timeouts
- Use configured containerPort in post-install notes

### CI

- Check formatting, vet and race-test; widen dependabot coverage

### Documentation

- Document probe metrics, supported schemes and exposure caveats
- Gate the fingerprint-change alert on probe_success

### Features

- Bump container tag; default tag from Chart appVersion
- Emit probe_success and probe_duration_seconds metrics
- Honor request context and Prometheus scrape timeout headroom
- Use http.Server with timeouts and graceful shutdown
- Modernize chart
- Support legacy ingress APIs on old clusters
- Fully automated release pipeline

### Other

- Bump github.com/sirupsen/logrus from 1.9.3 to 1.9.4
- Bump github.com/prometheus/client_golang from 1.14.0 to 1.23.2

### Refactoring

- Replace logrus with stdlib log/slog

### Testing

- Cover getFingerprint, getScrapeTimeout and probeHandler
## [0.4.0] - 2025-04-26

### Other

- Update packages dependencies
- Create dependabot.yml
- Update test action; don't upload test artifacts
- Improve logging, error handling and allow changing listing port and timeouts
- Improve README.md
- Build binaries for many more platforms
- Add version management from git tags
- Add GitHub Actions release workflow
- Bump github.com/sirupsen/logrus from 1.9.0 to 1.9.3
- Run docker with non-root user
- Build and upload docker images with creating a release
- Use latest Github actions versions
- Fix release workflow
- Fix and simplify build process
- Fix docker build in release workflow
- Fix docker build in release workflow
## [0.3.0] - 2022-10-03

### Other

- Fix wrong service name in prometheus config example
- Add prometheus query example
- Extend README with info about how to get fingerprints
- Add MacOS Silicon builds to Makefile
- Unify filenames. Use dashes everywhere
- Switch to logrus as logging library
- Bumb version to 0.3.0
- Add Action to run tests
## [0.2.0] - 2020-02-18

### Bug Fixes

- Fix wrong dockerhub repo

### CI

- Build docker image with intermediate container

### Other

- Initial commit
- Add existing project code
- Set name and date in LICENSE file
- Cleanup Makefile
- Add basic helm chart
- Add some simple html page to root uri, also for health check
- Bump version to 0.2.0
