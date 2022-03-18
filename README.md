Creates a copy of a minidump with sensitive data overwritten with zero.

Currently it ensures there are no sensitive filenames in the modules list
and overwrites any memory bytes with 0 if they are not a pointer to
memory contained inside a loaded module.
