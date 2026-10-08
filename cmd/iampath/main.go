// Command iampath finds AWS IAM privilege-escalation paths offline from the
// output of `aws iam get-account-authorization-details`.
package main

import (
	"os"

	"github.com/Opsbreak/iampath/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
