# Ghidra WHDLoad Snapshot Loader

This is a loadable module for [Ghidra](https://ghidra-sre.org/), the software
engineering suite from the United States National Security Agency. Specifically,
it contains a loader for reading the "dump" files created by
[WHDLoad](http://whdload.de/), which is a program designed to support dynamic
patching of classic Amiga games and other software to run from a hard disk.

WHDLoad offers to generate dump files whenever the target program encounters a
CPU error or incorrect use of the WHDLoad "resident loader" API. Users can also
configure WHDLoad to generate a dump file on demand when a particular key is
pressed using the [`DebugKey`](http://whdload.de/docs/en/opt.html#DebugKey)
option, or to create a dump file of the state of the system on exit using the
[`CoreDump`](http://whdload.de/docs/en/opt.html#CoreDump) option.

However it's created, a dump file contains various information about the state
of the system at the time it was created:

* The content of the program's "base memory" (chip RAM starting at address zero).
* The content of the program's expansion memory, if any.
* The content of the helper program used to patch this particular program to
  run correctly in the WHDLoad environment.
* The values of the CPU registers.
* Some values from the custom chip registers (those that are readable, or all
  if "snooping" was enabled.)
* Values from the two CIA chips.

The Ghidra WHDLoad Snapshot loader uses the information in the dump file to
reconstruct a partial memory map containing memory regions described in the
dump file, and loads the memory contents from the snapshot into those regions.
This allows analysis of the system state at the instant the snapshot was
created, which can be useful for understanding how a particular Amiga game works
or how it is being patched to work with WHDLoad.

For example, the author used this loader to investigate a bug in a particular
WHDLoad-based program he was working on. The bug ultimately turned out to be
incorrect alignment of an object in memory, which was easy to see using type
annotations in Ghidra's disassembly view.

Along with reconstructing the memory map, the WHDLoad Snapshot Loader includes
a number of other extra features to help you get started quickly with analysis:

* It understands the layout of a WHDLoad program and can automatically identify
  the "game loader" entry point using information in the program's header,
  marking it as a function called `start` which has the appropriate signature.

* It automatically constructs struct types for the WHDLoad program header and
  for the "resident loader" jump table, subsetting it correctly based on the
  program's declared WHDLoad version number, to make it easier to see at a
  glance where and how the WHDLoad API is being used.

* It includes a custom dynamic data type `ResloadPatchList`, which can be
  assigned to a memory address that is passed to the `resload_Patch` function
  to automatically frame each of the individual patch instructions to make them
  easier to scan in the disassembly pane.

* It includes a `CopperInst` data type which can be applied to a memory address
  containing a single copper instruction to get a mnemonic representation of
  that instruction, including whether it is a `MOVE`, `WAIT`, or `SKIP`
  instruction and which registers or scan locations it works with.

* It automatically annotates the CPU's vector table with a struct type to
  make it easier to see which vector is which and to jump from the vector table
  to the exception handler functions in memory.

* It annotates the custom chip register area of memory with a struct type that
  identifies which register occupies each location. That in turn makes writes
  and reads on those register addresses more visible in disassembly.

The above features often allow quickly developing a sense of the structure of
the program by finding its entry points, interrupt handlers, I/O functions
using particular custom chip registers, etc.
