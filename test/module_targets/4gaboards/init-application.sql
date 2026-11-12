CREATE ROLE module_app LOGIN PASSWORD 'module-target-application-db-password';
CREATE DATABASE module_app OWNER module_app;
