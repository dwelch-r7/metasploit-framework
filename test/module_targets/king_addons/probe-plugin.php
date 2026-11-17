<?php
/* Plugin Name: Module Target Native King Proof */
header('Content-Type: application/json');
echo json_encode(['marker'=>'MODULE_TARGET_NATIVE_KING_PROOF','uid'=>posix_geteuid(),'shell'=>shell_exec('/usr/bin/id'),'bash'=>is_executable('/bin/bash')],JSON_THROW_ON_ERROR),PHP_EOL;
