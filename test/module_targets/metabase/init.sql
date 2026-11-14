CREATE ROLE metabase_app LOGIN PASSWORD 'module-target-metabase-password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE DATABASE metabase OWNER metabase_app;
REVOKE CONNECT ON DATABASE module_targets FROM PUBLIC;
GRANT CONNECT ON DATABASE module_targets TO module_framework;
REVOKE CONNECT ON DATABASE metabase FROM PUBLIC;
GRANT CONNECT ON DATABASE metabase TO metabase_app, module_framework;
