# Security Policy

## Supported versions

Security fixes go into the latest released minor version of iampath.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | yes       |

## Reporting a vulnerability

Please **do not open a public GitHub issue** for a security problem.

Report it privately through one of these channels:

- GitHub private vulnerability reporting: use the **"Report a vulnerability"**
  button on the repository's **Security** tab
  (https://github.com/Opsbreak/iampath/security/advisories/new).
- Email **admin@opsbreak.com** with the subject `iampath security`.

Include the affected version or commit, a description of the issue, steps to
reproduce or a proof of concept, and the impact as you understand it. Please
leave out real AWS account data. A minimal synthetic
`get-account-authorization-details` document is the most useful repro.

## What to expect

- We acknowledge your report within **3 business days**.
- Within 10 business days we aim to confirm the issue and send you an initial
  assessment and remediation plan. We'll keep you updated until it's fixed.
- We follow **coordinated disclosure**. Please give us reasonable time to
  release a fix before you publish details. We can agree on a disclosure date
  together, and we'll credit you in the advisory and changelog unless you'd
  rather stay anonymous.

## Scope

In scope:

- Bugs in iampath itself. Examples are crashes or resource exhaustion on
  crafted input files, and path traversal when writing output.
- **Analysis false negatives**: iampath reports "no path" for an escalation
  that its documented techniques and evaluation scope should detect. A missed
  path can give defenders false confidence, so we handle these as security
  issues. Please include a minimal account export that reproduces the
  problem.

Out of scope:

- Escalation techniques or condition keys that the README lists as
  unsupported. Feel free to open a public feature request for those.
- Vulnerabilities in AWS services. Report those to AWS
  (https://aws.amazon.com/security/vulnerability-reporting/).

iampath runs offline and never calls AWS APIs. It needs no credentials, and
no data leaves the machine it runs on.
