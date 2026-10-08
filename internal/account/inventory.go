package account

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Opsbreak/iampath/internal/policy"
)

// LambdaFunction is a Lambda function and its execution role.
type LambdaFunction struct {
	Name    string
	ARN     string
	RoleARN string
}

// EC2Instance is an EC2 instance and its instance profile.
type EC2Instance struct {
	ID                 string
	ARN                string
	State              string
	InstanceProfileARN string
	Tags               map[string]string
}

// CodeBuildProject is a CodeBuild project and its service role.
type CodeBuildProject struct {
	Name           string
	ARN            string
	ServiceRoleARN string
}

// LoadSCPLevel loads one level of service control policies from a file and
// appends it to the account. The file may contain:
//   - a single policy document,
//   - a JSON array of policy documents,
//   - the output of `aws organizations describe-policy`, or
//   - a JSON array of describe-policy outputs.
//
// Every --scp file is treated as one level of the organization hierarchy:
// SCPs inside one file are OR-ed, separate files are AND-ed.
func (a *Account) LoadSCPLevel(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pols, err := ParseSCPs(b, filepath.Base(path))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	hasAllow := false
	for _, p := range pols {
		for _, st := range p.Doc.Statement {
			if st.Effect == policy.Allow {
				hasAllow = true
			}
		}
	}
	if !hasAllow {
		a.warnf("SCP file %s contains no Allow statement: every action will be denied at this level (did you forget FullAWSAccess?)", path)
	}
	a.SCPLevels = append(a.SCPLevels, pols)
	return nil
}

// ParseSCPs parses SCP content; see LoadSCPLevel for accepted shapes.
func ParseSCPs(b []byte, name string) ([]policy.NamedPolicy, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, fmt.Errorf("empty SCP file")
	}
	var items []json.RawMessage
	if b[0] == '[' {
		if err := json.Unmarshal(b, &items); err != nil {
			return nil, err
		}
	} else {
		items = []json.RawMessage{b}
	}
	var out []policy.NamedPolicy
	for i, it := range items {
		var probe struct {
			Policy *struct {
				PolicySummary struct {
					Name string `json:"Name"`
					Arn  string `json:"Arn"`
				} `json:"PolicySummary"`
				Content string `json:"Content"`
			} `json:"Policy"`
			Name     string          `json:"Name"`
			Document json.RawMessage `json:"Document"`
		}
		if err := json.Unmarshal(it, &probe); err != nil {
			return nil, err
		}
		np := policy.NamedPolicy{Kind: policy.KindSCP, Source: "scp"}
		var doc *policy.Document
		var err error
		switch {
		case probe.Policy != nil:
			np.Name, np.ARN = probe.Policy.PolicySummary.Name, probe.Policy.PolicySummary.Arn
			doc, err = policy.Parse([]byte(probe.Policy.Content))
		case len(probe.Document) > 0:
			np.Name = probe.Name
			doc, err = policy.Parse(probe.Document)
		default:
			doc, err = policy.Parse(it)
		}
		if err != nil {
			return nil, fmt.Errorf("SCP %d: %w", i, err)
		}
		if np.Name == "" {
			np.Name = doc.ID
		}
		if np.Name == "" {
			np.Name = fmt.Sprintf("%s#%d", name, i)
		}
		np.Doc = doc
		out = append(out, np)
	}
	return out, nil
}

// LoadLambdaFunctions loads the output of `aws lambda list-functions`.
func (a *Account) LoadLambdaFunctions(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw struct {
		Functions []struct {
			FunctionName string `json:"FunctionName"`
			FunctionArn  string `json:"FunctionArn"`
			Role         string `json:"Role"`
		} `json:"Functions"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, f := range raw.Functions {
		a.Lambdas = append(a.Lambdas, LambdaFunction{Name: f.FunctionName, ARN: f.FunctionArn, RoleARN: f.Role})
	}
	return nil
}

// LoadEC2Instances loads the output of `aws ec2 describe-instances`.
func (a *Account) LoadEC2Instances(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw struct {
		Reservations []struct {
			OwnerID   string `json:"OwnerId"`
			Instances []struct {
				InstanceID         string `json:"InstanceId"`
				IamInstanceProfile *struct {
					Arn string `json:"Arn"`
				} `json:"IamInstanceProfile"`
				State struct {
					Name string `json:"Name"`
				} `json:"State"`
				Placement struct {
					AvailabilityZone string `json:"AvailabilityZone"`
				} `json:"Placement"`
				Tags []rawTag `json:"Tags"`
			} `json:"Instances"`
		} `json:"Reservations"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, r := range raw.Reservations {
		acct := r.OwnerID
		if acct == "" {
			acct = a.ID
		}
		for _, in := range r.Instances {
			region := strings.TrimRight(in.Placement.AvailabilityZone, "abcdefghijklmnopqrstuvwxyz")
			if region == "" {
				region = "*"
			}
			inst := EC2Instance{
				ID:    in.InstanceID,
				ARN:   fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, acct, in.InstanceID),
				State: in.State.Name,
				Tags:  tags(in.Tags),
			}
			if in.IamInstanceProfile != nil {
				inst.InstanceProfileARN = in.IamInstanceProfile.Arn
			}
			a.Instances = append(a.Instances, inst)
		}
	}
	return nil
}

// LoadCodeBuildProjects loads the output of `aws codebuild
// batch-get-projects`.
func (a *Account) LoadCodeBuildProjects(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var raw struct {
		Projects []struct {
			Name        string `json:"name"`
			Arn         string `json:"arn"`
			ServiceRole string `json:"serviceRole"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, p := range raw.Projects {
		a.CodeBuild = append(a.CodeBuild, CodeBuildProject{Name: p.Name, ARN: p.Arn, ServiceRoleARN: p.ServiceRole})
	}
	return nil
}
