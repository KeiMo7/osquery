# Column pruning and predicate pushdown

This document describes the on-demand column computation ("column pruning")
and the predicate pushdown machinery available to table implementations.

## Motivation

A table's `generate()`/`generator()` historically populated every column for
every row, regardless of whether the query actually referenced the column.
Some columns are disproportionately expensive: for example the `processes`
table performs several `readlink(2)`/file reads per process for columns such
as `path`, `cwd`, `root`, `cmdline`, `label` and `on_disk`. When a query only
selects three columns but the table computes all twenty seven, the wasted
work dominates the query time.

Predicate pushdown has the analogous problem at the row level: a `WHERE`
clause on an indexed column must reach the table implementation so it can
avoid generating rows that the SQL layer would only discard afterwards.

## Switch

Column pruning is controlled by the `--enable_column_pruning` flag and is
**off by default**, preserving the historical "compute every column"
behavior byte-for-byte. The flag only affects what a table is *allowed* to
skip; it never changes result semantics:

```sh
osqueryi --enable_column_pruning "SELECT pid, name FROM processes"
```

When the flag is off, `QueryContext::isColumnUsed()` keeps returning `true`
for every column and every pruning helper degrades to full computation.

## How the used column set is derived

SQLite reports the columns referenced by a query plan through
`sqlite3_index_info::colUsed` during `xBestIndex`. The virtual table layer
converts this bitmask into:

- `QueryContext::colsUsed`, the set of column names referenced by the query.
- `QueryContext::colsUsedBitset`, the same information indexed by column
  position (the 64th bit is the SQLite overflow marker).

The bitmask is per table scan, so:

- In a join each table receives its own independent column requirements.
- A subquery and an outer reference to the same table are separate scans and
  SQLite merges the requirements of each scan individually; nothing is shared
  across scans, so a row is never computed twice "to satisfy both scopes".
- Aggregates such as `COUNT(*)` reference no columns, `MIN(x)` references
  only `x`, and `SELECT pid FROM ...` references only `pid`.

Before a table is allowed to skip a column, the requested set is expanded to
the **effective used set**:

1. Columns carrying constraints (`WHERE col = ...`) are always included,
   because their values are needed to evaluate the predicate even when the
   column is not in the select list.
2. Column dependency groups declared by the table are added. If column `A`
   depends on `B`, requesting `A` forces `B` to be computed as well.
3. Side effect groups are added as whole units. A column that updates a
   cache, populates per-process state, or otherwise has side effects may only
   be skipped together with every column in its group; if any member of the
   group is requested the entire group runs, keeping side effect ordering and
   consistency identical to the unpruned path.
4. Column aliases are resolved to their canonical target before expansion.

An explicitly empty requested set is a column-free query such as
`COUNT(*)`: the effective set contains only constraint columns, if any.
If anything is unknown — an extension that does not transmit `colUsed`,
a star select reported without a usable bitmask, or the flag being off —
the effective set falls back to "all columns". A skipped column is simply
returned as SQL NULL, exactly like the existing
`test_used_columns_default` behavior.

## Declaring column dependencies

Tables opt in by overriding `TablePlugin::columnDependencies()`:

```cpp
ColumnDependencyMap columnDependencies() const override {
  return {
      // on_disk reuses the readlink() result of path.
      {"on_disk", {"path"}},
      // A side effect group: reading any of these columns refreshes the
      // same per-process cached state, so they always run together.
      {"disk_bytes_read", {"disk_bytes_written"}},
      {"disk_bytes_written", {"disk_bytes_read"}},
  };
}
```

The map declares `column -> extra columns that must be computed whenever the
key column is computed`. The framework closes the relation transitively and
merges it with the side effect groups. Tables that do not override the method
keep the empty default and are treated as having no dependencies, which is
correct for independently computed columns.

## Lazy rows

`LazyTableRow` (see `osquery/sql/lazy_table_row.h`) is a `TableRow`
implementation that registers a computation callback per column. Columns are
evaluated lazily on the first `get_column()` call from SQLite, cached for the
lifetime of the row, and never evaluated if the column is not in the
effective used set:

```cpp
auto row = makeLazyTableRow(used_columns);
row->setColumn("pid", [&] { return pid; });
row->setLazyColumn("cmdline", [&] { return readProcCMDLine(pid); });
results.push_back(std::move(row));
```

Eager `setColumn()` callbacks run inside `generate()` and preserve the
original side effect ordering (stat/status parsing before file reads, etc.).
Lazy callbacks run during result materialization; a callback that throws is
attributed to its column in the error message and, unless
`--ignore_table_exceptions` is set, propagated as before.

## Predicate pushdown

Constraints on columns declared `index`, `additional` or `required` in the
table spec are accepted in `xBestIndex`, bound through `argv` in `xFilter`
and delivered to `generate()` through `QueryContext::constraints`. A table
consumes them with `context.constraints["pid"].getAll(EQUALS)` /
`context.hasConstraint(...)` and restricts row generation accordingly.

Constraints that the table does not consume are never marked as satisfied:
SQLite retains the predicate and re-evaluates it on the produced rows, so an
unsupported or unrecognized predicate can never cause extra rows to leak.
The `processes`, `file` and `process_open_sockets` tables all restrict their
input enumeration (`/proc` listing, glob expansion) to the pushed-down
constraints, and fall back to a full enumeration when no usable constraint
exists.

## Observability

When `--planner` is enabled each scan additionally reports the requested
column count, the effective (post-expansion) column count and the number of
columns actually evaluated by lazy rows. Table implementations increment the
counters in `QueryContext::metrics` (`rows_generated`, `columns_computed`,
`scans`) which makes before/after comparisons independent of wall clock
noise.
