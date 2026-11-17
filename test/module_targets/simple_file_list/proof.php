<?php
header('Content-Type: application/json');
echo json_encode(['marker'=>'MODULE_TARGET_NATIVE_SFL_PROOF','uid'=>posix_geteuid(),'shell'=>shell_exec('/usr/bin/id'),'bash'=>is_executable('/bin/bash')],JSON_THROW_ON_ERROR),PHP_EOL;
