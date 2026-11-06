# AGENTS.md

`jauntin/two-factor-auth`: Laravel package sending email Verification Codes for
admin login in gatherguard, gbli-events and basicare-plus. `README.md` holds usage
and the design constraints (`## Development`); read it before changing behaviour.

## Release contract

- **Semver** is the promise to consumers. A minor release installs on their next
  `composer update` and needs zero code, config, or published-file change on
  their side. Anything that breaks that is a major, and needs the owner's OK.
- **Blast radius**: before changing public API, config, schema, or the login flow,
  grep `../gatherguard/backend`, `../gbli-events/backend` and
  `../basicare-plus/backend` for every touched symbol. Name the affected call
  sites in the PR.
- **Upgrade note** in `README.md` for every consumer-visible change (new
  migration, new config key, changed flow) in the same PR.
- **Tag** `X.Y.Z` on `main` after merge (no `v` prefix), only when the user asks.

## Quality gate

```sh
composer install && vendor/bin/pint && vendor/bin/phpstan && vendor/bin/phpunit
```

Done = all three green. Fix root causes; leave `@phpstan-ignore` and baselines
alone. PR CI re-runs Pint and auto-commits its output to the branch.

- Every behaviour change ships with a test; a bug fix gets a regression test named
  after the invariant.
- Security path: changes touching code generation, storage, or validation get a
  `/security-review` before the PR.

## Specs

`/brainstorming` specs live in `docs/superpowers/specs/` for the branch's lifetime.
Before merge, move durable constraints into `README.md` `## Development` or a
code comment at the constraint site, then `git rm` the spec.
