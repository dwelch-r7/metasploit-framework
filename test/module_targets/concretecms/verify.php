<?php
$catalog=json_decode(file_get_contents('/lab/vendor.json'),true);
$version=getenv('CONCRETE_VERSION');
if(!isset($catalog[$version]))throw new RuntimeException('Unsupported fixture version');
$record=$catalog[$version];
if(PHP_VERSION!==$record['php'])throw new RuntimeException('Unexpected PHP runtime');
foreach($record['files'] as $path=>$expected) {
    if(hash_file('sha256','/app/'.$path)!==$expected['sha256'])throw new RuntimeException('Original source differs: '.$path);
}
foreach($record['absent'] as $path)if(file_exists('/app/'.$path))throw new RuntimeException('Removed file present: '.$path);
echo json_encode(['version'=>$version,'php'=>PHP_VERSION,'files'=>count($record['files']),'removed_absent'=>$record['absent']])."\n";
