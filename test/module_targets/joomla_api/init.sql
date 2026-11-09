CREATE DATABASE joomla_root;
CREATE DATABASE joomla_prefix;
CREATE DATABASE joomla_fixed;
CREATE DATABASE joomla_hidden;
CREATE USER 'module_target'@'%' IDENTIFIED BY 'module-target-db-password';
GRANT ALL ON joomla_root.* TO 'module_target'@'%';
GRANT ALL ON joomla_prefix.* TO 'module_target'@'%';
GRANT ALL ON joomla_fixed.* TO 'module_target'@'%';
GRANT ALL ON joomla_hidden.* TO 'module_target'@'%';
