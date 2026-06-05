#!/bin/sh
# Startup script for the IRIS API service.
# Seeds the database from demo_data/ if it doesn't exist yet.

set -e

mkdir -p data/logs data/models exports/sigma_rules policies
mkdir -p data/sandbox/public data/sandbox/private data/sandbox/admin

# Seed sandbox files
echo "This is a public readme file." > data/sandbox/public/readme.txt
printf "date,value,notes\n2026-01-01,100,normal operations\n2026-01-02,200,standard reporting\n2026-01-03,150,quarterly target met\n2026-01-04,300,growth confirmed" > data/sandbox/public/report.csv
echo "db_password=supersecret123\napi_key=sk-abc123\nservice_token=tok-xyz789" > data/sandbox/private/credentials.txt
echo '{"users": [{"id": 1, "name": "alice", "role": "engineer"}, {"id": 2, "name": "bob", "role": "manager"}]}' > data/sandbox/private/user_data.json
echo "system_version: 1.0\nadmin_email: admin@company.com\ndebug: false" > data/sandbox/admin/system_config.yaml

# Seed demo database if missing
if [ ! -f data/logs/agentguard.db ]; then
    echo "Seeding demo database from demo_data/..."
    cp demo_data/agentguard.db data/logs/agentguard.db
    echo "Database seeded: $(du -h data/logs/agentguard.db | cut -f1)"
fi

echo "Starting IRIS API..."
exec uvicorn api.main:app --host 0.0.0.0 --port 8000 --log-level warning
