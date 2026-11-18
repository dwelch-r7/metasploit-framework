CREATE USER 'module_reader'@'%' IDENTIFIED BY 'Module-target-read42!';
GRANT SELECT ON mysql.* TO 'module_reader'@'%';
CREATE USER 'module_denied'@'%' IDENTIFIED BY 'Module-target-denied42!';
CREATE USER 'comma,user'@'%' IDENTIFIED BY 'Module-target-comma42!';
CREATE USER 'quote''user'@'%' IDENTIFIED BY 'Module-target-quote42!';
CREATE USER 'space user'@'%' IDENTIFIED BY 'Module-target-space42!';
CREATE USER 'empty_hash'@'%';
