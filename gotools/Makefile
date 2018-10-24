#Copyright ArxanFintech Technology Ltd. 2017 All Rights Reserved.
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#		 http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#

GOTOOLS = golint govendor goimports misspell
GOTOOLS_BIN = $(patsubst %,$(GOPATH)/bin/%, $(GOTOOLS))

# go tool->path mapping
go.fqp.govendor  := github.com/kardianos/govendor
go.fqp.golint    := golang.org/x/lint/golint
go.fqp.goimports := golang.org/x/tools/cmd/goimports
go.fqp.misspell   := github.com/client9/misspell/cmd/misspell

# project dependencies
go.dep.sdk-go-common := github.com/arxanchain/sdk-go-common/...
go.dep.safebox-sdk-go := github.com/arxanchain/safebox-sdk-go/...
go.dep.gockv1    := gopkg.in/h2non/gock.v1

all: $(GOTOOLS_BIN) dep

# Default rule for gotools uses the name->path map for a generic 'go get' style build
gotool.%:
	$(eval TOOL = ${subst gotool.,,${@}})
	@echo "Building $(TOOL)"
	go get ${go.fqp.${TOOL}}

$(GOPATH)/bin/%:
	$(eval TOOL = ${subst $(GOPATH)/bin/,,${@}})
	@$(MAKE) gotool.$(TOOL)

dep:
	@echo "Downloading dependencies"
	go get ${go.dep.gockv1}
	go get -u ${go.dep.sdk-go-common}
	go get -u ${go.dep.safebox-sdk-go}

.PHONY: clean
clean:
	-@rm -f $(GOTOOLS_BIN) ||:
