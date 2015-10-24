# baba

## Building

    $ cmake . && make

## Usage

When command line arguments are described in this section,
asterisks (*) are used to indicate a default behaviour.

`baba` spawns a process specified on the command line,
and doesn't return until its descendants
(not only immediate children) return.

It always creates a new process group for itself and its descendants.

Daemonization will cause descendants to be reattached to
`baba` rather than `init`.

`baba` intercepts all the signals it can.
It either swallows them (`-fN`),
forwards them to its process group (`-fG`*) or
forward them to its initial child (`-fC`).

It logs about its own execution and what happens to its descendants,
with 3 levels available:
`-lC`* for critical only,
`-lV` for verbose,
`-lT` for trace.

It can either always return `0` (`-tN`),
track only its initial child (`-tC`*),
or track all immediate children (`-tG`).

Its exit status can either mirror that of its initial child (`-eC`*)
or the number of tracked processes that failed, capped at `127` (`-eF`).
