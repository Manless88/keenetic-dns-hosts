SHELL := /bin/sh
VERSION := $(shell cat VERSION)

.DEFAULT_GOAL := package

package:
	python3 tools/build_ipk.py

entware: package

clean:
	rm -rf out dist
