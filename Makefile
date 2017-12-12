#
# Copyright ArxanFintech Technology Ltd. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
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

PROJECT_NAME=arxanchain/wallet-sdk-go
PKGNAME = github.com/$(PROJECT_NAME)

CGO_FLAGS = CGO_CFLAGS=" " CGO_LDFLAGS="-lstdc++ -lm -lz -lbz2 -lsnappy"
EXT_LDFLAGS= --ldflags '-extldflags "-lstdc++ -lm -static"'

ifneq ($(IS_RELEASE),true)
EXTRA_VERSION ?= snapshot-$(shell git rev-parse --short HEAD)
PROJECT_VERSION=$(BASE_VERSION)-$(EXTRA_VERSION)
else
PROJECT_VERSION=$(BASE_VERSION)
endif

# No sense rebuilding when non production code is changed
PROJECT_FILES = $(shell git ls-files | \
        grep -v _test.go$ | grep -v .md$ | grep -v ^.git | \
        grep -v ^LICENSE )

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
