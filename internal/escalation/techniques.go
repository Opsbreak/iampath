// Package escalation models well-known AWS IAM privilege-escalation
// techniques as edges in a principal graph and searches it for paths to
// administrator-equivalent access.
package escalation

import "sort"

// Category groups techniques by their effect.
type Category string

// Technique categories.
const (
	// CategorySelf techniques let a principal grant itself (or a principal
	// it controls) arbitrary permissions.
	CategorySelf Category = "permission-modification"
	// CategoryCredential techniques obtain credentials of another IAM user.
	CategoryCredential Category = "credential-access"
	// CategoryAssume techniques obtain a session of an IAM role.
	CategoryAssume Category = "role-assumption"
	// CategoryPassRole techniques pass a role to an AWS service and run
	// attacker-controlled code with it.
	CategoryPassRole Category = "passrole-compute"
	// CategoryHijack techniques take over existing compute that already
	// runs with a role.
	CategoryHijack Category = "compute-hijack"
)

// Technique describes a privilege-escalation primitive.
type Technique struct {
	ID          string
	Name        string
	Category    Category
	Permissions []string
	// Service is the service principal the passed role must trust
	// (PassRole techniques only).
	Service string
	// Inventory names the optional input required ("" if none).
	Inventory   string
	Description string
	// Exploitation explains, for defenders, what an attacker gains and
	// how the primitive is typically abused.
	Exploitation string
	Remediation  string
	// Weight is the relative complexity used to rank paths (lower is
	// easier/quieter).
	Weight int
}

// AdminTechnique is the pseudo technique used for the final hop from an
// administrator-equivalent principal to the ADMIN node.
var AdminTechnique = &Technique{ID: "ADMIN", Name: "administrator-equivalent", Weight: 0,
	Description: "The principal's effective permissions already allow * on * or iam:* on *."}

var techniques = []*Technique{
	{
		ID: "IAM-001", Name: "CreatePolicyVersion", Category: CategorySelf, Weight: 1,
		Permissions: []string{"iam:CreatePolicyVersion"},
		Description: "Create a new default version of a customer managed policy attached to the principal.",
		Exploitation: "iam:CreatePolicyVersion with --set-as-default replaces the effective content of the policy without " +
			"needing iam:SetDefaultPolicyVersion. Anyone who can do this on a policy attached to themselves (directly or via a group) " +
			"can grant themselves Action:* on Resource:*.",
		Remediation: "Never grant iam:CreatePolicyVersion on policies attached to the same principal. Scope the action to " +
			"specific policy ARNs owned by a deployment pipeline, and alert on CreatePolicyVersion events in CloudTrail.",
	},
	{
		ID: "IAM-002", Name: "SetDefaultPolicyVersion", Category: CategorySelf, Weight: 1,
		Permissions: []string{"iam:SetDefaultPolicyVersion"},
		Description: "Roll an attached managed policy back to an older, more permissive non-default version.",
		Exploitation: "Managed policies keep up to five versions. If an older version was broader (a common leftover after " +
			"tightening a policy), switching the default version silently restores those permissions.",
		Remediation: "Delete unused non-default policy versions and restrict iam:SetDefaultPolicyVersion to administrators.",
	},
	{
		ID: "IAM-003", Name: "AttachUserPolicy", Category: CategorySelf, Weight: 1,
		Permissions:  []string{"iam:AttachUserPolicy"},
		Description:  "Attach a managed policy such as AdministratorAccess to a user.",
		Exploitation: "Attaching arn:aws:iam::aws:policy/AdministratorAccess to oneself is immediate and complete escalation.",
		Remediation: "Restrict iam:Attach*Policy, or constrain it with an iam:PolicyARN condition listing approved policies " +
			"and enforce permissions boundaries on created principals.",
	},
	{
		ID: "IAM-004", Name: "AttachGroupPolicy", Category: CategorySelf, Weight: 1,
		Permissions:  []string{"iam:AttachGroupPolicy"},
		Description:  "Attach a managed policy to a group the user belongs to.",
		Exploitation: "Equivalent to AttachUserPolicy but via group membership; affects every member of the group.",
		Remediation:  "Restrict iam:AttachGroupPolicy and use an iam:PolicyARN condition to allow-list policies.",
	},
	{
		ID: "IAM-005", Name: "AttachRolePolicy", Category: CategorySelf, Weight: 1,
		Permissions:  []string{"iam:AttachRolePolicy"},
		Description:  "Attach a managed policy to a role the attacker is, or can become.",
		Exploitation: "A role (or a user able to assume it) that can attach AdministratorAccess to that role becomes admin.",
		Remediation:  "Restrict iam:AttachRolePolicy; require permissions boundaries via iam:PermissionsBoundary conditions.",
	},
	{
		ID: "IAM-006", Name: "PutUserPolicy", Category: CategorySelf, Weight: 1,
		Permissions: []string{"iam:PutUserPolicy"},
		Description: "Write an inline policy on a user.",
		Exploitation: "An inline policy with Action:* Resource:* on oneself. Policies scoped to user/${aws:username} " +
			"(\"manage your own policies\") are a classic self-escalation.",
		Remediation: "Do not delegate iam:PutUserPolicy, even on the caller's own user.",
	},
	{
		ID: "IAM-007", Name: "PutGroupPolicy", Category: CategorySelf, Weight: 1,
		Permissions:  []string{"iam:PutGroupPolicy"},
		Description:  "Write an inline policy on a group the user belongs to.",
		Exploitation: "Same as PutUserPolicy but via a group, granting every member the new permissions.",
		Remediation:  "Restrict iam:PutGroupPolicy to administrators.",
	},
	{
		ID: "IAM-008", Name: "PutRolePolicy", Category: CategorySelf, Weight: 1,
		Permissions:  []string{"iam:PutRolePolicy"},
		Description:  "Write an inline policy on a role the attacker is, or can become.",
		Exploitation: "Common in CI roles that manage their own permissions; the role can grant itself anything.",
		Remediation:  "Never let a role modify its own policies; use a separate, tightly-guarded deployment role.",
	},
	{
		ID: "IAM-009", Name: "AddUserToGroup", Category: CategorySelf, Weight: 1,
		Permissions:  []string{"iam:AddUserToGroup"},
		Description:  "Add the user to a group whose policies grant administrator access.",
		Exploitation: "Joining an Admins group is a single API call and is easy to miss among routine group changes.",
		Remediation:  "Scope iam:AddUserToGroup to specific low-privilege groups and alert on changes to privileged groups.",
	},
	{
		ID: "IAM-010", Name: "CreateAccessKey", Category: CategoryCredential, Weight: 1,
		Permissions:  []string{"iam:CreateAccessKey"},
		Description:  "Create an access key for another IAM user.",
		Exploitation: "Yields long-term credentials for the target user (each user may have two keys; a full key slot blocks it).",
		Remediation:  "Restrict iam:CreateAccessKey to user/${aws:username} and prefer IAM Identity Center over IAM users.",
	},
	{
		ID: "IAM-011", Name: "CreateLoginProfile", Category: CategoryCredential, Weight: 2,
		Permissions: []string{"iam:CreateLoginProfile"},
		Description: "Set a console password for another IAM user that has none.",
		Exploitation: "Grants console access as the target user. Fails if the user already has a login profile; MFA " +
			"enforcement policies may limit what the session can do.",
		Remediation: "Restrict iam:CreateLoginProfile to user/${aws:username} and to administrators.",
	},
	{
		ID: "IAM-012", Name: "UpdateLoginProfile", Category: CategoryCredential, Weight: 2,
		Permissions:  []string{"iam:UpdateLoginProfile"},
		Description:  "Reset the console password of another IAM user.",
		Exploitation: "Takes over console access of the target user (noisy: the legitimate user is locked out).",
		Remediation:  "Restrict iam:UpdateLoginProfile to user/${aws:username}; require MFA for console sessions.",
	},
	{
		ID: "IAM-013", Name: "UpdateAssumeRolePolicy", Category: CategoryAssume, Weight: 2,
		Permissions: []string{"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"},
		Description: "Rewrite a role's trust policy to trust the attacker, then assume it.",
		Exploitation: "After naming their own ARN in the trust policy, a same-account principal can assume the role. " +
			"Only an explicit Deny or an SCP on sts:AssumeRole stops the second step.",
		Remediation: "Restrict iam:UpdateAssumeRolePolicy to administrators; monitor trust-policy changes with AWS Config.",
	},
	{
		ID: "STS-001", Name: "AssumeRole", Category: CategoryAssume, Weight: 1,
		Permissions: []string{"sts:AssumeRole"},
		Description: "Assume a role whose trust policy allows the principal.",
		Exploitation: "Trust policies that name the account root delegate the decision to identity policies; " +
			"broad sts:AssumeRole grants (Resource:*) then expose every such role.",
		Remediation: "Name specific principal ARNs in trust policies, add conditions (aws:PrincipalArn, sts:ExternalId, MFA) " +
			"and scope sts:AssumeRole in identity policies to the roles that are needed.",
	},
	{
		ID: "LAMBDA-001", Name: "PassRole+Lambda CreateFunction+InvokeFunction", Category: CategoryPassRole, Weight: 2,
		Service:     "lambda.amazonaws.com",
		Permissions: []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
		Description: "Create a Lambda function with a privileged execution role and invoke it.",
		Exploitation: "The function's code runs with the passed role's permissions and can, for example, attach " +
			"AdministratorAccess to the attacker's user.",
		Remediation: "Scope iam:PassRole to specific role ARNs and add an iam:PassedToService condition; keep Lambda " +
			"execution roles least-privilege.",
	},
	{
		ID: "LAMBDA-002", Name: "PassRole+Lambda CreateFunction+CreateEventSourceMapping", Category: CategoryPassRole, Weight: 3,
		Service:      "lambda.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"},
		Description:  "Create a Lambda function with a privileged role and trigger it via an event source mapping (DynamoDB, Kinesis, SQS).",
		Exploitation: "Works even without lambda:InvokeFunction: the event source invokes the function.",
		Remediation:  "Scope iam:PassRole with iam:PassedToService and restrict lambda:CreateEventSourceMapping.",
	},
	{
		ID: "LAMBDA-003", Name: "UpdateFunctionCode", Category: CategoryHijack, Weight: 2, Inventory: "--lambda-functions",
		Permissions:  []string{"lambda:UpdateFunctionCode"},
		Description:  "Replace the code of an existing function whose execution role is more privileged.",
		Exploitation: "The new code runs with the function's role on the next invocation; no iam:PassRole is required.",
		Remediation:  "Restrict lambda:UpdateFunctionCode to deployment pipelines and enable code signing for Lambda.",
	},
	{
		ID: "EC2-001", Name: "PassRole+EC2 RunInstances", Category: CategoryPassRole, Weight: 3,
		Service:      "ec2.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "ec2:RunInstances"},
		Description:  "Launch an instance with an instance profile for a privileged role.",
		Exploitation: "User data or SSH/SSM access to the instance yields the role's credentials from IMDS.",
		Remediation:  "Scope iam:PassRole to approved instance roles; require IMDSv2 and monitor RunInstances with instance profiles.",
	},
	{
		ID: "CFN-001", Name: "PassRole+CloudFormation CreateStack", Category: CategoryPassRole, Weight: 2,
		Service:      "cloudformation.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "cloudformation:CreateStack"},
		Description:  "Create a stack that CloudFormation deploys using a privileged service role.",
		Exploitation: "The template can create IAM users, keys or policies with the service role's permissions.",
		Remediation:  "Scope iam:PassRole for cloudformation.amazonaws.com and review which principals may create stacks.",
	},
	{
		ID: "GLUE-001", Name: "PassRole+Glue CreateDevEndpoint", Category: CategoryPassRole, Weight: 3,
		Service:      "glue.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "glue:CreateDevEndpoint"},
		Description:  "Create a Glue development endpoint with a privileged role and SSH into it.",
		Exploitation: "The endpoint exposes the role's credentials to whoever holds the SSH key.",
		Remediation:  "Restrict glue:CreateDevEndpoint (legacy feature) and scope iam:PassRole for glue.amazonaws.com.",
	},
	{
		ID: "GLUE-002", Name: "PassRole+Glue CreateJob+StartJobRun", Category: CategoryPassRole, Weight: 3,
		Service:      "glue.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "glue:CreateJob", "glue:StartJobRun"},
		Description:  "Create and run a Glue job whose script executes with a privileged role.",
		Exploitation: "Arbitrary Python/Scala runs with the role's permissions.",
		Remediation:  "Scope iam:PassRole for glue.amazonaws.com to dedicated, least-privilege Glue roles.",
	},
	{
		ID: "DP-001", Name: "PassRole+Data Pipeline", Category: CategoryPassRole, Weight: 4,
		Service:      "datapipeline.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"},
		Description:  "Create a Data Pipeline whose activities run shell commands with a privileged role.",
		Exploitation: "ShellCommandActivity executes attacker-chosen commands on pipeline resources.",
		Remediation:  "Data Pipeline is in maintenance mode; deny datapipeline:* where unused and scope iam:PassRole.",
	},
	{
		ID: "SM-001", Name: "PassRole+SageMaker CreateNotebookInstance", Category: CategoryPassRole, Weight: 3,
		Service:      "sagemaker.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"},
		Description:  "Create a notebook instance with a privileged role and open it in a browser.",
		Exploitation: "The Jupyter terminal runs with the notebook's execution role.",
		Remediation:  "Scope iam:PassRole for sagemaker.amazonaws.com and restrict presigned URL creation.",
	},
	{
		ID: "ECS-001", Name: "PassRole+ECS RegisterTaskDefinition+RunTask", Category: CategoryPassRole, Weight: 3,
		Service:      "ecs-tasks.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"},
		Description:  "Register a task definition with a privileged task role and run it on an existing cluster.",
		Exploitation: "The container receives the task role's credentials. Requires an existing cluster (any Fargate-capable cluster).",
		Remediation:  "Scope iam:PassRole for ecs-tasks.amazonaws.com to approved task roles.",
	},
	{
		ID: "SSM-001", Name: "SSM SendCommand", Category: CategoryHijack, Weight: 2, Inventory: "--ec2-instances",
		Permissions:  []string{"ssm:SendCommand"},
		Description:  "Run commands on an instance whose instance profile role is more privileged.",
		Exploitation: "Commands run as root on the instance and can read the role credentials from IMDS.",
		Remediation:  "Scope ssm:SendCommand by instance tags/ARNs and documents; avoid privileged instance profiles.",
	},
	{
		ID: "SSM-002", Name: "SSM StartSession", Category: CategoryHijack, Weight: 2, Inventory: "--ec2-instances",
		Permissions:  []string{"ssm:StartSession"},
		Description:  "Open an interactive Session Manager shell on an instance with a privileged instance profile.",
		Exploitation: "Interactive shell on the instance; IMDS exposes the role's credentials.",
		Remediation:  "Scope ssm:StartSession with resource tags and session documents; avoid privileged instance profiles.",
	},
	{
		ID: "CB-001", Name: "CodeBuild StartBuild (buildspec override)", Category: CategoryHijack, Weight: 2, Inventory: "--codebuild-projects",
		Permissions:  []string{"codebuild:StartBuild"},
		Description:  "Start a build of an existing project with an attacker-supplied buildspec.",
		Exploitation: "--buildspec-override runs arbitrary commands with the project's service role.",
		Remediation:  "Restrict codebuild:StartBuild on privileged projects and keep service roles least-privilege.",
	},
	{
		ID: "CB-002", Name: "PassRole+CodeBuild CreateProject+StartBuild", Category: CategoryPassRole, Weight: 3,
		Service:      "codebuild.amazonaws.com",
		Permissions:  []string{"iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"},
		Description:  "Create a CodeBuild project with a privileged service role and run a build.",
		Exploitation: "The buildspec runs arbitrary commands with the service role.",
		Remediation:  "Scope iam:PassRole for codebuild.amazonaws.com to dedicated build roles.",
	},
}

var techniqueByID = func() map[string]*Technique {
	m := map[string]*Technique{}
	for _, t := range techniques {
		m[t.ID] = t
	}
	return m
}()

// Techniques returns all techniques sorted by ID.
func Techniques() []*Technique {
	out := append([]*Technique(nil), techniques...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// TechniqueByID returns the technique with the given ID or nil.
func TechniqueByID(id string) *Technique {
	if id == AdminTechnique.ID {
		return AdminTechnique
	}
	return techniqueByID[id]
}
