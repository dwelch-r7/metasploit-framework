# Independent PHP payload control

This diagnostic uses the existing authenticated WordPress administrator upload
module with an explicitly selected inline PHP Meterpreter payload on the same
pinned core/PHP engine and measured app-to-host callback route. It separates
payload/lab failures from the unauthenticated RCE chain. Only app and MariaDB run;
the isolated host console has no reporting database. It does not establish RCE
chain or reporting coverage. Results must be recorded separately before counting
any accepted functional case.
