CREATE DATABASE IF NOT EXISTS piwigo CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON piwigo.* TO 'module_target'@'%';
