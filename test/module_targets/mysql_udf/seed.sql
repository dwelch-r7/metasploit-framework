CREATE USER 'udf_admin'@'%' IDENTIFIED BY 'Module-schema-password42!';
CREATE USER 'udf_no_file'@'%' IDENTIFIED BY 'Module-schema-password42!';
CREATE USER 'udf_no_catalog'@'%' IDENTIFIED BY 'Module-schema-password42!';
GRANT ALL PRIVILEGES ON *.* TO 'udf_admin'@'%';
GRANT SELECT,INSERT,DELETE ON mysql.* TO 'udf_no_file'@'%';
GRANT SELECT ON mysql.user TO 'udf_no_catalog'@'%';
GRANT FILE ON *.* TO 'udf_no_catalog'@'%';
