-- Workload for tragach-iowait (SPECS.md §5.2).
--
-- Scans a 2 GB table whose pages cannot all stay in the page cache once it
-- has been flushed. The bundled employee.fdb is too small to demonstrate
-- dominance — it lives entirely in cache after one read.
--
-- Prerequisite: run tests/workloads/build-large-db.sh once (creates
-- /var/lib/firebird/tragach-iowait-large.fdb, ~2 GB, ~15 min).
--
-- Run:
--
--   $(sudo grep -E '^ISC_(USER|PASSWORD)=' /opt/firebird-v5/SYSDBA.password \
--       | sed 's/^/export /')
--   sudo sh -c 'sync && echo 3 > /proc/sys/vm/drop_caches'
--   sudo tragach-iowait --interval 5s &
--   isql -i tests/workloads/iowait-basic.sql
--
-- Expected output: the `block I/O wait` bucket dominates the first scan
-- with stacks rooted in io_schedule / filemap_get_pages. A second scan in
-- the same session is cache-warm and shows almost no block I/O.
-- The contended-UPDATE / futex-wait scenario is a separate manual check
-- (run two concurrent isql sessions hitting the same row).

CONNECT 'localhost:/var/lib/firebird/tragach-iowait-large.fdb';
SET STATS ON;

-- Cold-cache full-table scan. Pages are 8 KB, ~250k rows of 8 KB BLOB each,
-- so the scan must hit disk for ~2 GB of data when the page cache is empty.
SELECT COUNT(*) FROM BIG_T;

EXIT;
