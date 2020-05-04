#!/bin/bash

set -eux
gradle
unzip -o dist/ghidra_9.1.1_PUBLIC_*_ghidra-amiga-whdload.zip -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"
