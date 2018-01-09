#!/bin/bash
#
# Copyright Greg Haskins All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running goimports"
for i in `ls -d */|grep -v gotools |grep -v scripts`
do
	OUTPUT="$(goimports -l $i)"
	if [[ $OUTPUT ]]; then
		echo "Contain goimports errors: "
		echo $OUTPUT
		exit 1
	fi
done
