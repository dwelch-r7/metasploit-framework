CREATE ROLE pgpass_user LOGIN PASSWORD 'pgpass-lab-password';
CREATE DATABASE pgpass_lab OWNER pgpass_user;
CREATE DATABASE "pgpass:db" OWNER pgpass_user;
CREATE ROLE "pgpass:user" LOGIN PASSWORD 'pgpass-lab-password';
CREATE ROLE escape_user LOGIN PASSWORD 'pg:pass\word:tail';
GRANT CONNECT ON DATABASE pgpass_lab TO "pgpass:user", escape_user;
