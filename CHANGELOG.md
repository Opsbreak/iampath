# Changelog

All notable changes to this project are recorded in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-08

### Added

- Offline analysis of `aws iam get-account-authorization-details` output,
  including the URL-encoded policy documents returned by the raw API.
- Policy evaluation engine:
  - Action/NotAction, Resource/NotResource and Principal/NotPrincipal.
  - `*` and `?` wildcards and IAM policy variables (`${aws:username}`,
    `${aws:PrincipalTag/...}`, default values, `${*}`).
  - Condition operators String*, Arn*, Bool, IpAddress/NotIpAddress and Null,
    with `IfExists` and `ForAnyValue`/`ForAllValues` qualifiers. Any other
    operator, and any key that can't be known offline, evaluates to "unknown"
    and is reported as conditional.
  - AWS evaluation order: explicit deny, then each SCP level, then identity
    policies, then the permissions boundary.
  - Role trust policy evaluation: principal ARN, account root, wildcard,
    service principals and conditions.
- 28 escalation techniques. They cover IAM, STS, PassRole into Lambda, EC2,
  CloudFormation, Glue, Data Pipeline, SageMaker, ECS and CodeBuild, and
  hijacking existing Lambda functions, SSM-managed instances and CodeBuild
  projects through optional inventory files.
- Weighted graph search: up to K shortest loopless paths (Yen's algorithm)
  from each principal to a virtual ADMIN node, `--max-hops`, and cycle
  detection (Tarjan SCC).
- Commands: `paths`, `who-can`, `explain`, `techniques` and `version`.
- Output formats: text, JSON, Graphviz DOT, Mermaid and SARIF 2.1.0.
  `--fail-on-paths` exits with status 3 so CI can gate on findings.
- Optional inputs: `--scp` (one file per hierarchy level),
  `--lambda-functions`, `--ec2-instances` and `--codebuild-projects`.

[Unreleased]: https://github.com/Opsbreak/iampath/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Opsbreak/iampath/releases/tag/v0.1.0
