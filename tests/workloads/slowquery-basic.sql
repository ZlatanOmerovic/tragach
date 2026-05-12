-- Workload for tragach-slowquery (SPECS.md §5.1, post-amendment commit e1ae278).
--
-- Goal: exercise BOTH execute paths so slowquery emits one event per statement:
--   * DSQL_execute       — non-cursor (singleton SELECT, DML if added)
--   * DSQL_execute_immediate — SET TRANSACTION here
--   * openCursor+fetchNext — multi-row SELECT (the typical client SELECT)
--
-- Connection uses TCP localhost. The local-file path needs /tmp/firebird/ access
-- which is owned by the firebird user; TCP routes through the server process and
-- avoids that. SYSDBA password is generated at install time and stored in
-- /opt/firebird-v5/SYSDBA.password — export ISC_USER=sysdba and ISC_PASSWORD
-- before running, e.g.:
--
--   $(grep -E '^ISC_(USER|PASSWORD)=' /opt/firebird-v5/SYSDBA.password \
--       | sed 's/^/export /')
--   isql -i tests/workloads/slowquery-basic.sql
--
-- Compare against the engine-internal timing isql reports under `SET STATS ON`.
-- Note: isql's "Elapsed time" includes network round-trip + result formatting,
-- so tragach's prepare_ns + execute_ns will be smaller (engine-only time).

CONNECT 'localhost:/opt/firebird-v5/examples/empbuild/employee.fdb';
SET STATS ON;

-- 1. Singleton SELECT — routes through DSQL_execute (non-cursor).
SELECT FIRST_NAME, LAST_NAME FROM EMPLOYEE WHERE EMP_NO = 2;

-- 2. Multi-row SELECT — routes through openCursor + fetchNext.
SELECT COUNT(*) FROM EMPLOYEE;

-- 3. Multi-table JOIN, multi-row — exercises the optimizer at prepare time.
SELECT D.DEPARTMENT, COUNT(E.EMP_NO)
  FROM DEPARTMENT D
  LEFT JOIN EMPLOYEE E ON E.DEPT_NO = D.DEPT_NO
  GROUP BY D.DEPARTMENT;

-- 4. Aggregation on a different table.
SELECT FISCAL_YEAR, SUM(PROJECTED_BUDGET)
  FROM PROJ_DEPT_BUDGET
  GROUP BY FISCAL_YEAR
  ORDER BY FISCAL_YEAR;

EXIT;
