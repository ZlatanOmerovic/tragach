-- Workload for tragach-iowait (SPECS.md §5.2).
--
-- Designed to drive the block-I/O-wait bucket to dominate: a self-join cross
-- product over EMPLOYEE forces a scan that exceeds the page cache after
-- `echo 3 > /proc/sys/vm/drop_caches`. Without dropping caches first, this
-- exercises CPU + cache only; block I/O won't appear.
--
-- Recommended invocation:
--
--   $(grep -E '^ISC_(USER|PASSWORD)=' /opt/firebird-v5/SYSDBA.password \
--       | sed 's/^/export /')
--   sudo sh -c 'sync && echo 3 > /proc/sys/vm/drop_caches'
--   sudo tragach-iowait --interval 5s &
--   isql -i tests/workloads/iowait-basic.sql
--
-- For the futex-wait bucket to dominate, run two concurrent isql sessions
-- against the same row — that lock-wait is the contended UPDATE scenario
-- SPECS §5.2 calls out. Not scripted here because it needs two processes;
-- documented as a manual two-terminal check.

CONNECT 'localhost:/opt/firebird-v5/examples/empbuild/employee.fdb';

-- Cold-cache self-join: ~10⁴ rows × itself, forced sort, no cache help.
SELECT COUNT(*)
  FROM EMPLOYEE A, EMPLOYEE B, EMPLOYEE C
  WHERE A.EMP_NO < B.EMP_NO
    AND B.EMP_NO < C.EMP_NO;

-- A second pass exercises the cache-warm path (no block I/O expected).
SELECT COUNT(*)
  FROM EMPLOYEE A, EMPLOYEE B
  WHERE A.EMP_NO < B.EMP_NO;

EXIT;
