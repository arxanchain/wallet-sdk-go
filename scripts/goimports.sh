#!/bin/bash

set -e

declare -a arr=("./api")

for i in "${arr[@]}"
do
	OUTPUT="$(goimports -v -l $i)"
	if [[ $OUTPUT ]]; then
		echo "Contain goimports errors: "
		echo $OUTPUT
		exit 1
	fi
done
