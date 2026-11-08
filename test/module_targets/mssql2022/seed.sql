SET NOCOUNT ON;
IF DB_ID('module_target_test') IS NULL CREATE DATABASE module_target_test;
GO
USE module_target_test;
IF OBJECT_ID('dbo.module_target_evidence', 'U') IS NULL
BEGIN
  CREATE TABLE dbo.module_target_evidence (id int PRIMARY KEY, evidence varchar(64) NOT NULL);
  INSERT INTO dbo.module_target_evidence VALUES (1, 'module-target-sql-marker');
END;
SELECT evidence FROM dbo.module_target_evidence WHERE id = 1;
SELECT 'MODULE_TARGET_HASH=' + CONVERT(varchar(max), password_hash, 1)
  FROM master.sys.sql_logins WHERE name = 'sa';
