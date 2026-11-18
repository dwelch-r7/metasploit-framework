#!/bin/bash
set -eu
python /opt/module-target/deploy.py > /opt/airflow/module-target-deploy.log 2>&1
airflow initdb > /opt/airflow/module-target-init.log 2>&1
python /opt/module-target/seed.py > /opt/airflow/module-target-seed.log 2>&1
if [[ ${MODULE_TARGET_MODE:-vulnerable} != no_scheduler ]]; then
 airflow scheduler > /opt/airflow/module-target-scheduler.log 2>&1 &
fi
exec airflow webserver
