#!/usr/bin/env sh
# Regenerates the example outputs in this directory from testdata/.
# Run from the repository root: sh examples/generate.sh
set -eu

go build -o ./iampath-example ./cmd/iampath
trap 'rm -f ./iampath-example' EXIT

FULL="--scp testdata/scp-root.json --lambda-functions testdata/lambda-functions.json --ec2-instances testdata/ec2-instances.json --codebuild-projects testdata/codebuild-projects.json"

./iampath-example paths -i testdata/account.json > examples/paths-baseline.txt
# shellcheck disable=SC2086
./iampath-example paths -i testdata/account.json $FULL > examples/paths-full.txt
# shellcheck disable=SC2086
./iampath-example paths -i testdata/account.json $FULL --format mermaid > examples/paths-full.mmd
# shellcheck disable=SC2086
./iampath-example paths -i testdata/account.json $FULL --format dot > examples/paths-full.dot
./iampath-example who-can -i testdata/account.json iam:PassRole arn:aws:iam::111122223333:role/service-role/LambdaAdminExec > examples/who-can-passrole.txt
./iampath-example explain -i testdata/account.json erin iam:PutUserPolicy arn:aws:iam::111122223333:user/erin > examples/explain-boundary.txt
./iampath-example explain -i testdata/account.json --scp testdata/scp-root.json frank iam:AttachUserPolicy arn:aws:iam::111122223333:user/frank > examples/explain-scp.txt
./iampath-example explain -i testdata/account.json dave sts:AssumeRole arn:aws:iam::111122223333:role/BreakGlassAdmin > examples/explain-trust.txt
echo "examples regenerated"
