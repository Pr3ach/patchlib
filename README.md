# patchlib
Simple Windows lib to make file or process patching easier and faster. Have a look at the src/patchlib.h,
it basically exports 4 functions:

* `int patch_raw(int8_t *filename, void offset, void *bytes, SIZE_T count)`
* `int patch_load(int8_t *name, void *addr, void *bytes, SIZE_T count)`
* `int patch_open(int8_t *name, void *addr, void *bytes, SIZE_T count)`
* `int patch_raw_replace(int8_t *file_name, uint8_t *s, uint8_t *r, SIZE_T s_sz, SIZE_T r_sz, int global)`

These have the following usages:

* `patch_raw` is used for file patching (ie. on disk).
* `patch_load` creates a process, suspend it's main thread, patch and resume it.
* `patch_open` is basically the same as above, but on a process.
* `patch_raw_replace` search & replace a given byte sequence.

These functions return 1 on success, 0 otherwise.
For concrete examples, check out the "tests" folder in this repo.
