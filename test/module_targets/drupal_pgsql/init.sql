CREATE USER module_target WITH PASSWORD 'module-target-db-password';
CREATE DATABASE drupal_root OWNER module_target;
CREATE USER module_framework WITH PASSWORD 'module-target-framework-db-password';
CREATE DATABASE module_targets OWNER module_framework;
