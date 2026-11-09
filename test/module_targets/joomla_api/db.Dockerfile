FROM mariadb:11.2.2@sha256:c5077bb44d13a3f34dadb5a15861149e29b3251d1e24036d2dad9611dc9d940b
COPY init.sql /docker-entrypoint-initdb.d/module-target.sql
