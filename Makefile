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
# -------------------------------------------------------------
# This makefile defines the following targets
#
#   - all (default) - builds all targets and runs all tests/checks
#   - checks - runs all tests/checks
#   - unit-test - runs the go-test based unit tests
#   - gotools - installs go tools like golint
#   - linter - runs all code checks
#   - clean - cleans the build area

EXECUTABLES = go git
# target apidocs need not check $EXECUTABLES
ifneq ($(MAKECMDGOALS),apidocs)
K := $(foreach exec,$(EXECUTABLES),\
	$(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH: Check dependencies")))
endif

# SUBDIRS are components that have their own Makefiles that we can invoke
SUBDIRS = gotools
SUBDIRS:=$(strip $(SUBDIRS))

PROJECT_FILES = $(shell git ls-files)

all: checks

checks: linter unit-test

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	cd $@ && $(MAKE)

unit-test: gotools
	@./scripts/goUnitTests.sh

linter: gotools
	@echo "LINT: Running code checks.."
	@echo "Running go vet"
	@./scripts/govet.sh
	@echo "Running goimports"
	@./scripts/goimports.sh

.PHONY: clean
clean:
	-@rm -rf build ||:
