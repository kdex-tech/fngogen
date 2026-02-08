#!/bin/sh

set -e

cd ${WORKING_DIRECTORY}
source .env

cd ${TARGET_DIR}

[ ! -f "go.mod" ] && go mod init function

echo "${FUNCTION_SPEC}" > openapi-spec.json

cat <<EOF > generate.go
package project

//go:generate go run github.com/ogen-go/ogen/cmd/ogen@latest --target api --clean openapi-spec.json
EOF

go generate ./...

/fngogen

go mod tidy
go vet ./...
go fmt ./...

tree .