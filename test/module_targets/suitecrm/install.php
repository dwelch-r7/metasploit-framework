<?php
chdir('/var/www/html');
$_SERVER['SERVER_PORT'] = '80';
$_SERVER['SERVER_NAME'] = 'localhost';
$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['PHP_SELF'] = '/install.php';
$_SERVER['REQUEST_URI'] = '/install.php?goto=SilentInstall&cli=true';
$_REQUEST['goto'] = 'SilentInstall';
$_REQUEST['cli'] = 'true';
require 'install.php';
