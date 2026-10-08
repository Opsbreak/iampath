// Package synth generates large synthetic authorization-details documents
// for benchmarks and scale tests. The shape loosely follows real
// organisations: most principals are low-privilege, a few hold dangerous
// IAM, STS or PassRole permissions, and roles trust services, the account
// root or other roles.
package synth

import (
	"encoding/json"
	"fmt"
	"math/rand"
)

// Account is the account ID used for generated data.
const Account = "210987654321"

type m = map[string]any

func doc(stmts ...m) m {
	s := make([]any, len(stmts))
	for i := range stmts {
		s[i] = stmts[i]
	}
	return m{"Version": "2012-10-17", "Statement": s}
}

func allow(action any, resource any) m {
	return m{"Effect": "Allow", "Action": action, "Resource": resource}
}

// Generate returns a get-account-authorization-details JSON document with
// approximately n principals (60% users, 40% roles).
func Generate(n int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	arn := func(kind, name string) string { return fmt.Sprintf("arn:aws:iam::%s:%s/%s", Account, kind, name) }
	nUsers := n * 6 / 10
	nRoles := n - nUsers
	nGroups := 40

	var policies []any
	addPolicy := func(name string, d m) string {
		a := arn("policy", name)
		policies = append(policies, m{"PolicyName": name, "Arn": a, "Path": "/", "DefaultVersionId": "v1",
			"PolicyVersionList": []any{m{"VersionId": "v1", "IsDefaultVersion": true, "Document": d}}})
		return a
	}
	adminPol := "arn:aws:iam::aws:policy/AdministratorAccess"
	policies = append(policies, m{"PolicyName": "AdministratorAccess", "Arn": adminPol, "Path": "/", "DefaultVersionId": "v1",
		"PolicyVersionList": []any{m{"VersionId": "v1", "IsDefaultVersion": true, "Document": doc(allow("*", "*"))}}})

	services := []string{"lambda.amazonaws.com", "ec2.amazonaws.com", "ecs-tasks.amazonaws.com", "glue.amazonaws.com", "codebuild.amazonaws.com"}
	readPols := make([]string, 20)
	for i := range readPols {
		svc := []string{"s3", "ec2", "dynamodb", "sqs", "sns", "logs", "cloudwatch", "lambda", "kms", "rds"}[i%10]
		readPols[i] = addPolicy(fmt.Sprintf("team-%02d-read", i), doc(
			allow([]string{svc + ":Get*", svc + ":List*", svc + ":Describe*"}, "*"),
			allow([]string{"s3:GetObject", "s3:PutObject"}, fmt.Sprintf("arn:aws:s3:::team-%02d-*/*", i)),
		))
	}

	var groups []any
	for g := 0; g < nGroups; g++ {
		att := []any{m{"PolicyName": fmt.Sprintf("team-%02d-read", g%20), "PolicyArn": readPols[g%20]}}
		if g == 0 {
			att = []any{m{"PolicyName": "AdministratorAccess", "PolicyArn": adminPol}}
		}
		groups = append(groups, m{"GroupName": fmt.Sprintf("group-%02d", g), "Path": "/", "Arn": arn("group", fmt.Sprintf("group-%02d", g)),
			"AttachedManagedPolicies": att, "GroupPolicyList": []any{}})
	}

	roleName := func(i int) string { return fmt.Sprintf("role-%04d", i) }
	var roles []any
	for i := 0; i < nRoles; i++ {
		name := roleName(i)
		var trust m
		var inline []any
		att := []any{}
		switch k := i % 10; {
		case k < 5: // service roles
			trust = doc(m{"Effect": "Allow", "Principal": m{"Service": services[r.Intn(len(services))]}, "Action": "sts:AssumeRole"})
		case k < 8: // team roles assumable from the account
			trust = doc(m{"Effect": "Allow", "Principal": m{"AWS": "arn:aws:iam::" + Account + ":root"}, "Action": "sts:AssumeRole"})
		default: // chained roles trusting another role
			trust = doc(m{"Effect": "Allow", "Principal": m{"AWS": arn("role", roleName(r.Intn(nRoles)))}, "Action": "sts:AssumeRole"})
		}
		switch {
		case r.Intn(100) < 2:
			att = append(att, m{"PolicyName": "AdministratorAccess", "PolicyArn": adminPol})
		case r.Intn(100) < 10:
			inline = append(inline, m{"PolicyName": "chain", "PolicyDocument": doc(allow("sts:AssumeRole", arn("role", roleName(r.Intn(nRoles)))))})
		case r.Intn(100) < 3:
			inline = append(inline, m{"PolicyName": "self-manage", "PolicyDocument": doc(allow("iam:PutRolePolicy", arn("role", name)))})
		default:
			p := readPols[r.Intn(len(readPols))]
			att = append(att, m{"PolicyName": "read", "PolicyArn": p})
		}
		rm := m{"RoleName": name, "Path": "/", "Arn": arn("role", name), "AssumeRolePolicyDocument": trust,
			"RolePolicyList": inline, "AttachedManagedPolicies": att}
		if i%10 < 5 && r.Intn(4) == 0 {
			rm["InstanceProfileList"] = []any{m{"InstanceProfileName": name, "Arn": arn("instance-profile", name)}}
		}
		roles = append(roles, rm)
	}

	var users []any
	for i := 0; i < nUsers; i++ {
		name := fmt.Sprintf("user-%04d", i)
		var inline []any
		groupsOf := []any{fmt.Sprintf("group-%02d", 1+r.Intn(nGroups-1))}
		switch x := r.Intn(1000); {
		case x < 3:
			groupsOf = append(groupsOf, "group-00")
		case x < 40:
			inline = append(inline, m{"PolicyName": "assume", "PolicyDocument": doc(allow("sts:AssumeRole", arn("role", "role-0*")))})
		case x < 60:
			inline = append(inline, m{"PolicyName": "deploy", "PolicyDocument": doc(
				allow("iam:PassRole", arn("role", fmt.Sprintf("role-%d*", r.Intn(10)))),
				allow([]string{"lambda:CreateFunction", "lambda:InvokeFunction", "ec2:RunInstances"}, "*"))})
		case x < 65:
			inline = append(inline, m{"PolicyName": "keys", "PolicyDocument": doc(allow("iam:CreateAccessKey", arn("user", "*")))})
		case x < 70:
			inline = append(inline, m{"PolicyName": "self", "PolicyDocument": doc(allow("iam:PutUserPolicy", arn("user", "${aws:username}")))})
		case x < 80:
			inline = append(inline, m{"PolicyName": "mfa", "PolicyDocument": doc(m{"Effect": "Allow", "Action": "sts:AssumeRole",
				"Resource": "*", "Condition": m{"Bool": m{"aws:MultiFactorAuthPresent": "true"}}})})
		}
		users = append(users, m{"UserName": name, "Path": "/", "Arn": arn("user", name), "GroupList": groupsOf,
			"UserPolicyList": inline, "AttachedManagedPolicies": []any{}})
	}
	b, err := json.Marshal(m{"UserDetailList": users, "GroupDetailList": groups, "RoleDetailList": roles, "Policies": policies})
	if err != nil {
		panic(err)
	}
	return b
}
