# Contributing to routemap-engine

Thank you for your interest. This is the geolocation and parsing engine behind
the [Route Map](https://github.com/osintph/routemap) desktop app and
FalconEye's Route Map tab. Bug reports and ideas are welcome as
[issues](https://github.com/osintph/routemap-engine/issues).

## Before you open a pull request

- **The CLA.** Every pull request needs the [Contributor Licence Agreement](CLA.md)
  signed once by each author. A bot comments on your first pull request with
  one sentence to post; that is the signature. You keep your copyright and give
  the project a licence to use your contribution under any terms, including
  outside the AGPL, which keeps the project free to relicense later, including
  in a separate commercial product. If you are not comfortable with that,
  please open an issue instead.
- **Contributions may be declined**, for any reason, including ones that are
  correct and useful but do not fit the engine's direction. For anything larger
  than a small fix, open an issue first.

## How the code is kept

- No global mutable state: configuration (User-Agent, cache, budgets, sources)
  is passed in.
- Nothing leaves the machine that does not have to: only routable hostnames go
  to Hoiho, only public addresses to the IP database or resolver.
- Every external source runs under a hard time budget and contributes nothing
  when it runs out.
- User-supplied values in log lines go through `logsafe.tag()`.
- A regression test covers the class of bug, not only the instance.
- No em dashes anywhere.

## Licence

GNU AGPL-3.0; see [LICENSE](LICENSE). Contributions are accepted under the CLA.
