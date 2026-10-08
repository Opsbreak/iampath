# iampath

[![CI](https://github.com/Opsbreak/iampath/actions/workflows/ci.yml/badge.svg)](https://github.com/Opsbreak/iampath/actions/workflows/ci.yml)

**iampath finds AWS IAM privilege-escalation paths offline.** Give it the JSON
from `aws iam get-account-authorization-details` and it reports every user and
role that can reach administrator access, how many steps that takes, and how
each step is exploited and fixed. It never calls AWS and needs no credentials
at analysis time.

```text
user/bob --[STS-001 AssumeRole]--> role/CI-Deployer --[STS-001 AssumeRole]--> role/InfraAutomation --[STS-001 AssumeRole]--> role/OrgAdmin ==> ADMIN
```

## Why

After an attacker gets a foothold in AWS (a leaked access key, a compromised
CI job, an SSRF to instance metadata), the usual next step is IAM privilege
escalation. They chain permissions such as `iam:PassRole`,
`iam:CreatePolicyVersion` or an over-broad `sts:AssumeRole` until they hold
administrator access. These chains are hard to see in a console that shows
one policy at a time.

Most tools that look for them run live against the account with privileged
credentials. iampath is built for defenders who would rather not do that:

- **Offline and read-only.** It analyses a JSON export. You can run it in an
  air-gapped review, in CI against a nightly export, or on a snapshot taken
  during an incident.
- **Graph-based.** It finds multi-hop chains (user → role → role → admin),
  ranks them by complexity, lists up to K alternative paths per principal and
  reports cycles.
- **Explainable.** `iampath explain` prints a full evaluation trace: which
  statement allowed or denied, the permissions boundary, the SCPs and the
  trust policy.
- **Honest about uncertainty.** Conditions that can't be resolved offline
  (MFA, source IP, request time and so on) don't silently pass or fail. The
  path is reported as **conditional** and the unresolved condition is shown.

## Install

```sh
go install github.com/Opsbreak/iampath/cmd/iampath@latest
```

Or build from source (Go 1.22 or newer, standard library only):

```sh
git clone https://github.com/Opsbreak/iampath && cd iampath
go build -o iampath ./cmd/iampath
```

## Exporting the data

Run these commands with any principal that has read-only IAM access. Only the
first file is required.

```sh
# Required: users, groups, roles, inline and managed policies (all versions),
# permissions boundaries, trust policies and instance profiles.
aws iam get-account-authorization-details --output json > account.json

# Optional: service control policies. Use one file per level of the hierarchy
# (root, each OU on the path, the account). Run these from the management
# account or a delegated administrator.
aws organizations list-policies-for-target --target-id r-abcd --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id p-FullAWSAccess > scp-root-full.json
# Combine every SCP at one level into a JSON array of describe-policy outputs:
jq -s '.' scp-root-*.json > scp-root.json

# Optional inventories that enable compute-hijack techniques (run per region):
aws lambda list-functions --output json > lambda-functions.json
aws ec2 describe-instances --output json > ec2-instances.json
aws codebuild batch-get-projects \
  --names $(aws codebuild list-projects --query 'projects[]' --output text) > codebuild-projects.json
```

### Least-privilege permissions for the export

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IampathExportIAM",
      "Effect": "Allow",
      "Action": "iam:GetAccountAuthorizationDetails",
      "Resource": "*"
    },
    {
      "Sid": "IampathExportOptionalInventories",
      "Effect": "Allow",
      "Action": [
        "lambda:ListFunctions",
        "ec2:DescribeInstances",
        "codebuild:ListProjects",
        "codebuild:BatchGetProjects"
      ],
      "Resource": "*"
    },
    {
      "Sid": "IampathExportSCPs",
      "Effect": "Allow",
      "Action": [
        "organizations:ListPoliciesForTarget",
        "organizations:ListParents",
        "organizations:DescribePolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

The AWS managed policies `SecurityAudit` and `ReadOnlyAccess` also cover the
IAM, Lambda, EC2 and CodeBuild calls.

> The export holds your full IAM configuration. Treat it as sensitive: don't
> commit it, and delete it when you're done.

## Quickstart

```sh
# All escalation paths, as human-readable text
iampath paths -i account.json

# With SCPs and inventories
iampath paths -i account.json --scp scp-root.json --scp scp-ou-prod.json \
  --lambda-functions lambda-functions.json --ec2-instances ec2-instances.json \
  --codebuild-projects codebuild-projects.json

# Only paths from one principal, up to 5 alternatives each
iampath paths -i account.json --from user/alice -k 5

# Machine-readable output and graphs
iampath paths -i account.json --format json    > paths.json
iampath paths -i account.json --format sarif   > iampath.sarif
iampath paths -i account.json --format dot     | dot -Tsvg > paths.svg
iampath paths -i account.json --format mermaid > paths.mmd

# Who can perform an action on a resource?
iampath who-can -i account.json iam:PassRole arn:aws:iam::111122223333:role/service-role/LambdaAdminExec

# Why is (or isn't) an action allowed?
iampath explain -i account.json --scp scp-root.json frank iam:AttachUserPolicy arn:aws:iam::111122223333:user/frank

# What-if: re-evaluate with a request-context value set
iampath explain -i account.json --context aws:MultiFactorAuthPresent=true \
  dave sts:AssumeRole arn:aws:iam::111122223333:role/BreakGlassAdmin

# List the modelled techniques
iampath techniques
```

Principals can be named as `alice`, `user/alice`, `role/OrgAdmin` or by full
ARN. Flags may appear before or after positional arguments.

## Example output

This is real output from running iampath against the synthetic account in
[`testdata/`](testdata) with every optional input. `examples/generate.sh`
regenerates it, and [examples/](examples) also has the DOT and Mermaid
versions.

```console
$ iampath paths -i testdata/account.json --scp testdata/scp-root.json \n  --lambda-functions testdata/lambda-functions.json \n  --ec2-instances testdata/ec2-instances.json \n  --codebuild-projects testdata/codebuild-projects.json
iampath 0.1.0 - offline IAM privilege-escalation analysis
Account 111122223333: 28 principals, 35 escalation edges, 6 admin-equivalent principals.

Administrator-equivalent principals:
  role/BreakGlassAdmin      effective policy allows * on *
  role/EC2-AdminInstance    effective policy allows * on *
  role/OrgAdmin             effective policy allows * on *
  role/CodeBuildDeployRole  effective policy allows iam:* on *
  role/LambdaAdminExec      effective policy allows * on *
  user/heidi                effective policy allows * on *

Escalation paths: 14 principals can reach ADMIN (12 unconditionally, 2 only conditionally).

[1] role/InfraAutomation  (1 step, cost 1)
    role/InfraAutomation --[STS-001 AssumeRole]--> role/OrgAdmin ==> ADMIN

[2] user/alice  (1 step, cost 1)
    user/alice --[IAM-001 CreatePolicyVersion on arn:aws:iam::111122223333:policy/DeveloperPolicy]--> ADMIN

[3] user/ivan  (1 step, cost 1)
    path 1 (1 step, cost 1):
      user/ivan --[IAM-010 CreateAccessKey]--> user/heidi ==> ADMIN
    path 2 (2 steps, cost 2):
      user/ivan --[IAM-010 CreateAccessKey]--> user/alice --[IAM-001 CreatePolicyVersion on arn:aws:iam::111122223333:policy/DeveloperPolicy]--> ADMIN
    path 3 (2 steps, cost 2):
      user/ivan --[IAM-010 CreateAccessKey]--> user/judy --[IAM-009 AddUserToGroup on arn:aws:iam::111122223333:group/Admins (join group Admins)]--> ADMIN

[4] user/judy  (1 step, cost 1)
    user/judy --[IAM-009 AddUserToGroup on arn:aws:iam::111122223333:group/Admins (join group Admins)]--> ADMIN

[5] user/peggy  (1 step, cost 1)
    user/peggy --[IAM-002 SetDefaultPolicyVersion on arn:aws:iam::111122223333:policy/ReportingAnalystPolicy (restore version v1)]--> ADMIN

[6] role/CI-Deployer  (2 steps, cost 2)
    role/CI-Deployer --[STS-001 AssumeRole]--> role/InfraAutomation --[STS-001 AssumeRole]--> role/OrgAdmin ==> ADMIN

[7] role/EC2-AppServer  (1 step, cost 2)
    path 1 (1 step, cost 2):
      role/EC2-AppServer --[SSM-001 SSM SendCommand on arn:aws:ec2:ca-central-1:111122223333:instance/i-0a1b2c3d4e5f60718 (instance i-0a1b2c3d4e5f60718)]--> role/EC2-AdminInstance ==> ADMIN
    path 2 (1 step, cost 2):
      role/EC2-AppServer --[CB-001 CodeBuild StartBuild (buildspec override) on arn:aws:codebuild:ca-central-1:111122223333:project/infra-deploy (project infra-deploy)]--> role/CodeBuildDeployRole ==> ADMIN
    path 3 (1 step, cost 2):
      role/EC2-AppServer --[LAMBDA-003 UpdateFunctionCode on arn:aws:lambda:ca-central-1:111122223333:function:nightly-report (function nightly-report)]--> role/LambdaAdminExec ==> ADMIN

[8] user/carol  (1 step, cost 2)
    user/carol --[LAMBDA-001 PassRole+Lambda CreateFunction+InvokeFunction]--> role/LambdaAdminExec ==> ADMIN

[9] user/olivia  (1 step, cost 2)
    user/olivia --[LAMBDA-003 UpdateFunctionCode on arn:aws:lambda:ca-central-1:111122223333:function:nightly-report (function nightly-report)]--> role/LambdaAdminExec ==> ADMIN

[10] user/quinn  (1 step, cost 2)
    user/quinn --[CB-001 CodeBuild StartBuild (buildspec override) on arn:aws:codebuild:ca-central-1:111122223333:project/infra-deploy (project infra-deploy)]--> role/CodeBuildDeployRole ==> ADMIN

[11] user/trent  (1 step, cost 2)
    user/trent --[IAM-013 UpdateAssumeRolePolicy]--> role/OrgAdmin ==> ADMIN

[12] user/bob  (3 steps, cost 3)
    user/bob --[STS-001 AssumeRole]--> role/CI-Deployer --[STS-001 AssumeRole]--> role/InfraAutomation --[STS-001 AssumeRole]--> role/OrgAdmin ==> ADMIN

[13] user/dave  (1 step, cost 4, CONDITIONAL)
    user/dave --[STS-001 AssumeRole [conditional]]--> role/BreakGlassAdmin ==> ADMIN
      ! trust policy: Bool aws:MultiFactorAuthPresent=[true] (key not known offline)

[14] user/ken  (1 step, cost 5, CONDITIONAL)
    path 1 (1 step, cost 5):
      user/ken --[SSM-001 SSM SendCommand on arn:aws:ec2:ca-central-1:111122223333:instance/i-0a1b2c3d4e5f60718 (instance i-0a1b2c3d4e5f60718) [conditional]]--> role/EC2-AdminInstance ==> ADMIN
        ! ssm:SendCommand: IpAddress aws:SourceIp=[203.0.113.0/24 198.51.100.0/24] (key not known offline)
    path 2 (2 steps, cost 7):
      user/ken --[SSM-001 SSM SendCommand on arn:aws:ec2:ca-central-1:111122223333:instance/i-0fedcba9876543210 (instance i-0fedcba9876543210) [conditional]]--> role/EC2-AppServer --[SSM-001 SSM SendCommand on arn:aws:ec2:ca-central-1:111122223333:instance/i-0a1b2c3d4e5f60718 (instance i-0a1b2c3d4e5f60718)]--> role/EC2-AdminInstance ==> ADMIN
        ! ssm:SendCommand: IpAddress aws:SourceIp=[203.0.113.0/24 198.51.100.0/24] (key not known offline)
    path 3 (2 steps, cost 7):
      user/ken --[SSM-001 SSM SendCommand on arn:aws:ec2:ca-central-1:111122223333:instance/i-0fedcba9876543210 (instance i-0fedcba9876543210) [conditional]]--> role/EC2-AppServer --[CB-001 CodeBuild StartBuild (buildspec override) on arn:aws:codebuild:ca-central-1:111122223333:project/infra-deploy (project infra-deploy)]--> role/CodeBuildDeployRole ==> ADMIN
        ! ssm:SendCommand: IpAddress aws:SourceIp=[203.0.113.0/24 198.51.100.0/24] (key not known offline)

No path to ADMIN (7): role/GlueETLRole, role/LambdaThumbnailer, role/ReadOnlyAuditor, user/erin, user/frank, user/grace, user/svc-backup

Cycles (principals that can reach each other):
  role/CI-Deployer <-> role/InfraAutomation
```

Not every principal ends up on the path list:

- **erin** has `iam:PutUserPolicy` on herself, but her permissions boundary
  stops it.
- **frank** has `iam:AttachUserPolicy` on himself, but the SCP denies it.
  Without `--scp` he shows up as a one-step path.
- **ken** can pass roles only to `lambda.amazonaws.com`, so the EC2 PassRole
  path is rejected. His remaining route, SSM, depends on `aws:SourceIp`, so
  it's reported as conditional.

Why is erin blocked?

```console
$ iampath explain -i testdata/account.json erin iam:PutUserPolicy arn:aws:iam::111122223333:user/erin
Principal: user/erin (arn:aws:iam::111122223333:user/erin)
Request:   iam:PutUserPolicy on arn:aws:iam::111122223333:user/erin
Context:   aws:PrincipalAccount=111122223333 aws:PrincipalArn=arn:aws:iam::111122223333:user/erin aws:PrincipalIsAWSService=false aws:PrincipalTag/team=web aws:PrincipalType=User aws:userid=AIDATFESHO2P2ZV6YIKWZ aws:username=erin
           (other condition keys are unknown offline)

Policies evaluated:
  identity  SelfServiceIAM (inline)
  identity  DeveloperPolicy (group:Developers)
  boundary  DeveloperBoundary
  scp       (none supplied)

Matching statements:
  [identity] SelfServiceIAM (inline) stmt ManageOwnUserPolicies: Allow

Evaluation (AWS order):
  explicit deny          false
  identity               true
  permissions boundary   false

Decision: ImplicitDeny
  not allowed by permissions boundary DeveloperBoundary (permissions boundary)
```

Who can pass the admin Lambda execution role?

```console
$ iampath who-can -i testdata/account.json iam:PassRole arn:aws:iam::111122223333:role/service-role/LambdaAdminExec
PRINCIPAL                 DECISION     DETAIL
role/BreakGlassAdmin      allow        allowed by [identity] AdministratorAccess (managed) stmt #0: Allow
role/EC2-AdminInstance    allow        allowed by [identity] AdministratorAccess (managed) stmt #0: Allow
role/OrgAdmin             allow        allowed by [identity] AdministratorAccess (managed) stmt #0: Allow
role/CodeBuildDeployRole  allow        allowed by [identity] IAMFullAccess (managed) stmt #0: Allow
role/LambdaAdminExec      allow        allowed by [identity] AdministratorAccess (managed) stmt #0: Allow
user/carol                conditional  allowed conditionally: identity allow is conditional ([identity] LambdaDeployPolicy (managed) stmt PassLambdaRoles: Allow (conditional: StringEquals iam:PassedToService=[lambda.amazonaws.com] (key not known offline)))
user/heidi                allow        allowed by [identity] AdministratorAccess (group:Admins) stmt #0: Allow

6 principal(s) allowed, 1 conditionally, for iam:PassRole on arn:aws:iam::111122223333:role/service-role/LambdaAdminExec.
```


## How it works

1. **Load.** iampath parses the export into users (with group memberships),
   groups, roles, managed policies (every version) and permissions
   boundaries. It accepts both the CLI's decoded JSON and the URL-encoded
   documents from the raw API.
2. **Evaluate.** For each principal, the evaluation engine (`internal/policy`)
   answers concrete questions such as "can this principal call
   `iam:PassRole` on role X with `iam:PassedToService=lambda.amazonaws.com`?"
   It follows AWS's order: an explicit deny anywhere wins, then every SCP
   level must allow, then an identity policy must allow, then the permissions
   boundary must allow.
3. **Build edges.** Each technique becomes an edge in a graph whose nodes are
   principals plus a virtual `ADMIN` node:
   - *become* edges (`A → B`): A can obtain B's credentials or session.
   - *grant* edges (`A → ADMIN`): A can give itself, or a principal it can
     become, administrator permissions.
   - administrator-equivalent principals get a zero-cost edge to `ADMIN`.
4. **Search.** Yen's K-shortest-loopless-paths algorithm runs over a Dijkstra
   core. Edge weights reflect complexity (for example, assuming a role costs
   1 and passing a role to EC2 costs 3), and edges that depend on unresolved
   conditions cost 3 more, so unconditional paths rank first. Tarjan's
   algorithm reports cycles.

A principal is **administrator-equivalent** when its effective permissions
(identity policies ∩ boundary ∩ SCPs) allow `*` on `*` or `iam:*` on `*`.
iampath checks this with synthetic action names that only a wildcard grant
can match, so a narrow `Deny` doesn't hide an admin. A principal that can
grant itself admin in one step (for example `iam:PutUserPolicy` on itself)
appears as a one-step path ending at `ADMIN`.

## Techniques

| ID | Technique | Required permissions | Remediation |
|---|---|---|---|
| CB-001 | CodeBuild StartBuild (buildspec override) | `codebuild:StartBuild` (needs `--codebuild-projects`) | Restrict codebuild:StartBuild on privileged projects and keep service roles least-privilege. |
| CB-002 | PassRole+CodeBuild CreateProject+StartBuild | `iam:PassRole` + `codebuild:CreateProject` + `codebuild:StartBuild` (role trusts `codebuild.amazonaws.com`) | Scope iam:PassRole for codebuild.amazonaws.com to dedicated build roles. |
| CFN-001 | PassRole+CloudFormation CreateStack | `iam:PassRole` + `cloudformation:CreateStack` (role trusts `cloudformation.amazonaws.com`) | Scope iam:PassRole for cloudformation.amazonaws.com and review which principals may create stacks. |
| DP-001 | PassRole+Data Pipeline | `iam:PassRole` + `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` + `datapipeline:ActivatePipeline` (role trusts `datapipeline.amazonaws.com`) | Data Pipeline is in maintenance mode; deny datapipeline:* where unused and scope iam:PassRole. |
| EC2-001 | PassRole+EC2 RunInstances | `iam:PassRole` + `ec2:RunInstances` (role trusts `ec2.amazonaws.com`) | Scope iam:PassRole to approved instance roles; require IMDSv2 and monitor RunInstances with instance profiles. |
| ECS-001 | PassRole+ECS RegisterTaskDefinition+RunTask | `iam:PassRole` + `ecs:RegisterTaskDefinition` + `ecs:RunTask` (role trusts `ecs-tasks.amazonaws.com`) | Scope iam:PassRole for ecs-tasks.amazonaws.com to approved task roles. |
| GLUE-001 | PassRole+Glue CreateDevEndpoint | `iam:PassRole` + `glue:CreateDevEndpoint` (role trusts `glue.amazonaws.com`) | Restrict glue:CreateDevEndpoint (legacy feature) and scope iam:PassRole for glue.amazonaws.com. |
| GLUE-002 | PassRole+Glue CreateJob+StartJobRun | `iam:PassRole` + `glue:CreateJob` + `glue:StartJobRun` (role trusts `glue.amazonaws.com`) | Scope iam:PassRole for glue.amazonaws.com to dedicated, least-privilege Glue roles. |
| IAM-001 | CreatePolicyVersion | `iam:CreatePolicyVersion` | Never grant iam:CreatePolicyVersion on policies attached to the same principal. Scope the action to specific policy ARNs owned by a deployment pipeline, and alert on CreatePolicyVersion events in CloudTrail. |
| IAM-002 | SetDefaultPolicyVersion | `iam:SetDefaultPolicyVersion` | Delete unused non-default policy versions and restrict iam:SetDefaultPolicyVersion to administrators. |
| IAM-003 | AttachUserPolicy | `iam:AttachUserPolicy` | Restrict iam:Attach*Policy, or constrain it with an iam:PolicyARN condition listing approved policies and enforce permissions boundaries on created principals. |
| IAM-004 | AttachGroupPolicy | `iam:AttachGroupPolicy` | Restrict iam:AttachGroupPolicy and use an iam:PolicyARN condition to allow-list policies. |
| IAM-005 | AttachRolePolicy | `iam:AttachRolePolicy` | Restrict iam:AttachRolePolicy; require permissions boundaries via iam:PermissionsBoundary conditions. |
| IAM-006 | PutUserPolicy | `iam:PutUserPolicy` | Do not delegate iam:PutUserPolicy, even on the caller's own user. |
| IAM-007 | PutGroupPolicy | `iam:PutGroupPolicy` | Restrict iam:PutGroupPolicy to administrators. |
| IAM-008 | PutRolePolicy | `iam:PutRolePolicy` | Never let a role modify its own policies; use a separate, tightly-guarded deployment role. |
| IAM-009 | AddUserToGroup | `iam:AddUserToGroup` | Scope iam:AddUserToGroup to specific low-privilege groups and alert on changes to privileged groups. |
| IAM-010 | CreateAccessKey | `iam:CreateAccessKey` | Restrict iam:CreateAccessKey to user/${aws:username} and prefer IAM Identity Center over IAM users. |
| IAM-011 | CreateLoginProfile | `iam:CreateLoginProfile` | Restrict iam:CreateLoginProfile to user/${aws:username} and to administrators. |
| IAM-012 | UpdateLoginProfile | `iam:UpdateLoginProfile` | Restrict iam:UpdateLoginProfile to user/${aws:username}; require MFA for console sessions. |
| IAM-013 | UpdateAssumeRolePolicy | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Restrict iam:UpdateAssumeRolePolicy to administrators; monitor trust-policy changes with AWS Config. |
| LAMBDA-001 | PassRole+Lambda CreateFunction+InvokeFunction | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` (role trusts `lambda.amazonaws.com`) | Scope iam:PassRole to specific role ARNs and add an iam:PassedToService condition; keep Lambda execution roles least-privilege. |
| LAMBDA-002 | PassRole+Lambda CreateFunction+CreateEventSourceMapping | `iam:PassRole` + `lambda:CreateFunction` + `lambda:CreateEventSourceMapping` (role trusts `lambda.amazonaws.com`) | Scope iam:PassRole with iam:PassedToService and restrict lambda:CreateEventSourceMapping. |
| LAMBDA-003 | UpdateFunctionCode | `lambda:UpdateFunctionCode` (needs `--lambda-functions`) | Restrict lambda:UpdateFunctionCode to deployment pipelines and enable code signing for Lambda. |
| SM-001 | PassRole+SageMaker CreateNotebookInstance | `iam:PassRole` + `sagemaker:CreateNotebookInstance` + `sagemaker:CreatePresignedNotebookInstanceUrl` (role trusts `sagemaker.amazonaws.com`) | Scope iam:PassRole for sagemaker.amazonaws.com and restrict presigned URL creation. |
| SSM-001 | SSM SendCommand | `ssm:SendCommand` (needs `--ec2-instances`) | Scope ssm:SendCommand by instance tags/ARNs and documents; avoid privileged instance profiles. |
| SSM-002 | SSM StartSession | `ssm:StartSession` (needs `--ec2-instances`) | Scope ssm:StartSession with resource tags and session documents; avoid privileged instance profiles. |
| STS-001 | AssumeRole | `sts:AssumeRole` | Name specific principal ARNs in trust policies, add conditions (aws:PrincipalArn, sts:ExternalId, MFA) and scope sts:AssumeRole in identity policies to the roles that are needed. |

`iampath techniques --format json` prints the full catalogue, including the
exploitation notes for each technique.

Some rules apply to every technique:

- **PassRole edges** need `iam:PassRole` on the specific role ARN, evaluated
  with `iam:PassedToService` set to the technique's service. The role's
  trust policy must also trust that service, and EC2 needs an instance
  profile.
- **Permission-modification techniques** (IAM-001 to IAM-009) lead to
  `ADMIN` only if the target could actually become admin. A permissions
  boundary or SCP that caps the target blocks the edge. When the target is
  another principal, the attacker must also be able to become that principal
  in one step. The edge is labelled `...; then act as role/X via AssumeRole`.
- **Attach\*Policy** is evaluated with `iam:PolicyARN` set to
  `AdministratorAccess`, or to any customer managed policy in the export that
  grants admin, so `iam:PolicyARN` allow-lists are respected.
- **Trust policies.** When a trust policy names the caller's ARN directly (or
  `*`), no identity-policy allow is needed in the same account, but explicit
  denies, SCPs and a role's own permissions boundary still apply. When it
  names the account (`:root` or a bare account ID), the caller's identity
  policies must also allow `sts:AssumeRole`.

## Evaluation engine: scope and limitations

Supported:

- `Statement` as an object or an array. `Action`/`NotAction`,
  `Resource`/`NotResource` and `Principal`/`NotPrincipal` as a string, an
  array or (for principals) a map with `AWS`, `Service`, `Federated` or
  `CanonicalUser`.
- Case-insensitive action matching and case-sensitive resource matching,
  both with `*` and `?`.
- Policy variables in `Resource` and condition values: `${aws:username}`,
  `${aws:userid}`, `${aws:PrincipalTag/...}` and other request-context keys,
  `${key, 'default'}`, and `${*}`, `${?}`, `${$}`.
- Condition operators `StringEquals`, `StringNotEquals`,
  `StringEqualsIgnoreCase`, `StringNotEqualsIgnoreCase`, `StringLike`,
  `StringNotLike`, `ArnEquals`, `ArnLike`, `ArnNotEquals`, `ArnNotLike`,
  `Bool`, `IpAddress`, `NotIpAddress` and `Null`, with the `...IfExists`
  suffix and the `ForAnyValue:`/`ForAllValues:` set qualifiers. Missing keys
  follow AWS semantics: false, except for `IfExists`, negated operators and
  `ForAllValues`.
- SCPs as a list of hierarchy levels. Each `--scp` file is one level: SCPs in
  the same file are OR-ed and levels are AND-ed. SCPs don't apply to
  service-linked roles.
- Attacker-chosen resource names, such as a new Lambda function. An allow
  matches if any concrete name satisfies both patterns. A deny only blocks
  the edge if it covers every name the attacker could choose.

Request-context keys iampath knows offline: `aws:username`, `aws:userid`,
`aws:PrincipalArn`, `aws:PrincipalAccount`, `aws:PrincipalType`,
`aws:PrincipalIsAWSService` and `aws:PrincipalTag/*` (any tag not in the
export is treated as absent). Per technique it also sets
`iam:PassedToService` and `iam:PolicyARN`, and, for EC2 instances from the
inventory, `aws:ResourceTag/*`, `ec2:ResourceTag/*` and `ssm:resourceTag/*`.
You can set others with `explain --context key=value`.

**Conditional results.** Any other key, for example `aws:SourceIp`,
`aws:MultiFactorAuthPresent`, `aws:RequestedRegion`, `aws:SourceVpce`,
`aws:PrincipalOrgID`, `sts:ExternalId`, `aws:CurrentTime`, `aws:RequestTag/*`
or `aws:ResourceTag/*` on non-EC2 resources, is unknown. So is every
unsupported operator: `Numeric*`, `Date*`, `BinaryEquals` and so on. Unknown
values make a statement *conditional*:

- a conditional **Allow** produces an edge marked `[conditional]`, with the
  unresolved condition listed under the path.
- a conditional **Deny** doesn't block the edge, but marks it conditional
  ("a Deny statement may apply").

Conditional paths therefore lean towards reporting (over-approximation)
rather than hiding a possible escalation.

Not modelled. iampath may miss or over-report paths because of:

- **Resource-based policies other than role trust policies**: S3 bucket
  policies, KMS key policies, Lambda function policies, SQS/SNS policies and
  so on. A resource policy that grants access to a principal is ignored, and
  so is one that denies it.
- **Session policies, `sts:SourceIdentity`/`sts:TagSession` constraints and
  role chaining limits.** Role sessions are assumed to have the role's full
  permissions.
- **Cross-account access.** Analysis covers one account. Trust policies that
  name other accounts are evaluated, but principals in those accounts aren't
  modelled.
- **Identity Center, SAML and OIDC federation.** `Federated` principals are
  parsed but not used as attack sources.
- **Resource existence and state** beyond the optional inventories. For
  example, ECS-001 assumes a cluster exists, IAM-011 can't see whether a
  login profile already exists, and IAM-010 can't see whether both access-key
  slots are used.
- **Wildcard trust (`"Principal": "*"`)** is treated as naming the caller
  directly, so no identity permission is required. This is deliberately
  conservative.
- **Organisation management accounts.** SCPs never apply to them. Don't pass
  `--scp` when you analyse the management account.
- **Escalation through data rather than IAM**, for example reading secrets
  from SSM Parameter Store or Secrets Manager, or modifying code that other
  principals deploy, except for the inventory-based Lambda, SSM and CodeBuild
  techniques.
- **Techniques deliberately out of scope**: `iam:UpdateRole` (max session
  duration) and `iam:CreateServiceLinkedRole`, which don't grant privileges
  by themselves.

## Performance

Benchmarks run on a synthetic account with 2,000 principals (1,200 users and
800 roles) from `internal/synth`: `go test -run '^$' -bench . -benchtime 5x
-count 3 ./internal/graph ./internal/escalation`. Measured with Go 1.27.0,
windows/amd64, on an Intel Core i7-14700. The ranges cover three runs.

| Benchmark | Time/op | Notes |
|---|---|---|
| `BenchmarkLoad2000`: parse the export | 5.8–6.0 ms | about 93 MB/s |
| `BenchmarkBuildEdges2000`: evaluate every technique for every principal | 0.58–0.64 s | 22,114 edges |
| `BenchmarkAnalyze2000`: full pipeline, K=3 paths from every principal | 0.63–0.70 s | 97 principals with paths |
| `BenchmarkKShortestPaths2000`: Yen K=3 from all 2,000 nodes of a random graph | 0.27–0.33 s | graph search only |

## CI usage

`--fail-on-paths` exits with status **3** when any path is found. Exit
codes: 0 ok, 1 error, 2 usage error, 3 paths found.

```yaml
# .github/workflows/iam-escalation.yml (example)
name: IAM escalation check
on:
  schedule: [{ cron: "0 6 * * *" }]
permissions:
  contents: read
  id-token: write          # OIDC to a read-only audit role
  security-events: write   # upload SARIF to code scanning
jobs:
  iampath:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@<pinned-sha> # use a read-only role
        with:
          role-to-assume: arn:aws:iam::111122223333:role/iampath-readonly
          aws-region: ca-central-1
      - run: aws iam get-account-authorization-details --output json > account.json
      - uses: actions/setup-go@d35c59abb061a4a6fb18e82ac0862c26744d6ab5 # v5.5.0
        with:
          go-version: stable
      - run: go install github.com/Opsbreak/iampath/cmd/iampath@latest
      - run: iampath paths -i account.json --format sarif -o iampath.sarif
      - uses: github/codeql-action/upload-sarif@<pinned-sha>
        with:
          sarif_file: iampath.sarif
      - run: iampath paths -i account.json --fail-on-paths
```

Replace `<pinned-sha>` with the full commit SHA of the release you have
reviewed. If some paths are accepted risk, scope the gate with `--from`, or
compare the JSON output against a committed baseline.

## Development

```sh
go test ./...                      # table-driven, golden-file and CLI tests
go test -race ./...
go vet ./...
gofmt -l .
go test -run '^$' -bench . -benchmem ./internal/...
```

`testdata/account.json` is a synthetic account (ID `111122223333`) with 28
principals. It includes a 3-hop role chain, a PassRole+Lambda path, a
conditional (MFA) path, a path blocked by a permissions boundary, a path
blocked by an SCP, a policy-version rollback, a role cycle and principals
with no path. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add
techniques.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

MIT, Copyright (c) 2026 Opsbreak Inc. See [LICENSE](LICENSE).
