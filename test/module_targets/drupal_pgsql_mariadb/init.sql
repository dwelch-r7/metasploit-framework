CREATE DATABASE drupal_root;
CREATE USER 'module_target'@'%' IDENTIFIED BY 'module-target-db-password';
GRANT ALL ON drupal_root.* TO 'module_target'@'%';
