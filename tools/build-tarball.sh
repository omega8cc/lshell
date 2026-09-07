#!/bin/bash
# Build the BOA-fetched source tarball from the committed tree: dist/lshell-<version>.tar.gz
# extracting to lshell-<version>/ (what _if_fix_lshell in BOA.sh.txt expects under /var/opt).
# The version is read from lshell/variables.py; BOA pins the same string in
# _LSHELL_VRN / _LSHELL_CHK_VRN. Publish to files.boa.io/dev/src by hand.
set -e
cd "$(dirname "$0")/.."
_VRN=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' lshell/variables.py)
[ -n "${_VRN}" ] || { echo "ERROR: version not found in lshell/variables.py"; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "ERROR: tree not clean; commit first"; exit 1; }
mkdir -p dist
git archive --format=tar.gz --prefix="lshell-${_VRN}/" -o "dist/lshell-${_VRN}.tar.gz" HEAD
echo "INFO: dist/lshell-${_VRN}.tar.gz ($(git rev-parse --short HEAD))"
tar -tzf "dist/lshell-${_VRN}.tar.gz" | head -3
