# Governance

## Roles

- **Contributors**: anyone who submits a change under the DCO.
- **Maintainers**: listed in `MAINTAINERS.md`; review and merge changes, cut releases.
- **Trust-boundary reviewers**: a subset of maintainers who must approve changes to `workload/`,
  `infra/terraform/wip.tf`, the event schema and the shareable-report template.

## Decisions

Lazy consensus on pull requests. Changes to the trust boundary, the license, or the attestation policy need a
written proposal (`docs/proposals/`), a 7-day comment period, and approval from two-thirds of maintainers.

## Releases

Each release publishes the workload image digest, the reproducible-build recipe, SLSA provenance, the SBOM and
AIBOM, and a signed changelog entry describing every change that affects the measured image. Operators of hosted
services announce adoption of a new digest at least 14 days ahead so vendors can update their key-release
policies.

## Independence

The project should move to a neutral foundation (for example, the Confidential Computing Consortium or OpenSSF)
once it has maintainers from at least three organizations. No single company may hold more than half of the
maintainer seats after that move.
