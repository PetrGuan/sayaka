# Optional APFS private-size observations

The scanner requests `ATTR_CMNEXT_PRIVATESIZE` with
`ATTR_CMN_RETURNED_ATTRS` and `FSOPT_ATTR_CMN_EXTENDED`. The public SDK defines
the attribute in `sys/attr.h`; `getattrlistat` is available from macOS 10.10,
below the app's macOS 26 deployment target. Attribute constants have no separate
SDK availability annotation. Actual filesystem support is checked per response;
missing bits, unsupported calls, invalid values and failures remain unknown.
Logical and allocated measurements retain their existing behavior.

Apple's [vnode definition](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/vnode.h)
describes `va_private_size` per file. Its
[attribute packing implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/vfs/vfs_attrlist.c)
returns the private-size validity bit only when the filesystem supports it.
Never substitute a zero buffer value for a missing returned bit.

Project and cache sizing add this attribute to the existing bulk call; no
second walk or retained per-file index is introduced. Generic Space scans use
one additional no-follow metadata query relative to the admitted directory,
checking identity, type, flags and link count. No file contents are opened.
The existing read-only materialization policy remains in force. Multi-link
files conservatively have unknown private size because alias selection is not
established by this measurement. Unsupported bulk calls retain the existing
legacy cursor fallback. Directory totals are known only when coverage and every
regular-file measurement are complete; overflow also means unknown.

`private_bytes` is the sum of per-file exclusive storage, **not** the storage
exclusive to an arbitrary selection. Shared extents remain excluded even when
all their clones are selected. Moving an original outside the selection does
not break extent sharing or turn a clone's private size into its logical size.
Thus the issue's example must not require a 1 GB private result merely because
the original is outside the selection. No clone-ID heuristic tries to predict
which shared extents deletion would release.

The UI keeps its logical headline and allocated Space geometry. Optional
information appears only with complete known private/allocated values and a
private-size shortfall greater than 10% of allocation. It explicitly excludes
predictions of space recovered by deleting the selection. Unknown values omit
the explanation; observed zero remains zero. Simulator estimates and image
contents are unchanged. These observations do not grant cleanup authority and
are not added to cleanup plan identity or revalidation requirements.

Validation is compile-only plus bounded read-only production CLI observations.
Unit/UI tests are not executed. Clone fixtures, actual capacity change, and
visual owner acceptance are separate from these results.
