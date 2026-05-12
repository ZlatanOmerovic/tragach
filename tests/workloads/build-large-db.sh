#!/bin/bash
# Build a ~2 GB Firebird database for the tragach-iowait dominance test.
#
# Why this exists: the bundled `employee.fdb` is small enough to live entirely
# in the page cache after one read, so an iowait scan against it shows almost
# no block-I/O wait — which contradicts SPECS §5.2's "block I/O dominates
# during the scan" criterion. This script produces a database whose pages
# can't all stay in cache once you `echo 3 > /proc/sys/vm/drop_caches`,
# making the dominance check verifiable.
#
# We use BLOBs of 8 KB instead of CHAR/VARCHAR padding because Firebird
# applies RLE compression to row data — a CHAR(4000) of 'x' shrinks to a
# handful of bytes on disk. BLOBs are stored on dedicated pages, uncompressed,
# so 250 000 × 8 KB blobs land as ~2 GB on disk regardless of contents.
#
# Output: /var/lib/firebird/tragach-iowait-large.fdb (owned by the firebird
# user; on the real disk under /, not /tmp which is tmpfs on this VM).

set -euo pipefail

DB_DIR=/var/lib/firebird
DB=$DB_DIR/tragach-iowait-large.fdb
ROWS=${ROWS:-250000}

if [ ! -d "$DB_DIR" ]; then
    sudo mkdir -p "$DB_DIR"
    sudo chown firebird:firebird "$DB_DIR"
fi

if [ -f "$DB" ]; then
    echo "Already exists: $DB ($(du -h "$DB" | cut -f1))"
    echo "Remove it to regenerate: sudo rm $DB"
    exit 0
fi

if [ -z "${ISC_USER:-}" ] || [ -z "${ISC_PASSWORD:-}" ]; then
    # /opt/firebird-v5/SYSDBA.password is root-readable only; read via sudo.
    # shellcheck disable=SC1090
    source <(sudo -n grep -E '^ISC_(USER|PASSWORD)=' /opt/firebird-v5/SYSDBA.password \
        | sed 's/^/export /')
fi

echo "Creating $DB with $ROWS rows of 8 KB BLOB (~$(( ROWS * 8 / 1024 )) MB raw)..."
START=$(date +%s)

/opt/firebird-v5/bin/isql -q <<EOF
CREATE DATABASE 'localhost:$DB' PAGE_SIZE 8192;
COMMIT;

CREATE TABLE BIG_T (
    ID BIGINT NOT NULL,
    PAD BLOB SUB_TYPE TEXT
);
COMMIT;

INSERT INTO BIG_T(ID, PAD)
SELECT FIRST $ROWS
       ROW_NUMBER() OVER (),
       RPAD('x', 8000, 'x')
FROM RDB\$TYPES A, RDB\$TYPES B, RDB\$TYPES C;
COMMIT;
EXIT;
EOF

ELAPSED=$(( $(date +%s) - START ))
echo "Built $DB in ${ELAPSED}s ($(du -h "$DB" | cut -f1))"
