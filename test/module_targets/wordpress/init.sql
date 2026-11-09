CREATE DATABASE wp_root;
CREATE DATABASE wp_prefix;
CREATE DATABASE wp_plain;
CREATE DATABASE wp_blocked;
CREATE USER 'module_target'@'%' IDENTIFIED BY 'module-target-db-password';
GRANT ALL ON wp_root.* TO 'module_target'@'%';
GRANT ALL ON wp_prefix.* TO 'module_target'@'%';
GRANT ALL ON wp_plain.* TO 'module_target'@'%';
GRANT ALL ON wp_blocked.* TO 'module_target'@'%';
