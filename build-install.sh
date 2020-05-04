#!/bin/bash

set -eux
gradle
unzip -o dist/ghidra_9.1.1_PUBLIC_20200503_ghidra-amiga-whdload.zip -d "$GHIDRA_INSTALL_DIR/Ghidra/Extensions"
