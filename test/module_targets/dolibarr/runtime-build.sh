#!/bin/sh
set -eu
php -r 'echo json_encode(array("php"=>PHP_VERSION,"mysqlnd"=>extension_loaded("mysqlnd"),"source_sha256"=>hash_file("sha256","/usr/src/php.tar.xz")))."\n"; if(hash_file("sha256","/usr/src/php.tar.xz")!==getenv("PHP_SHA256")) exit(1);'
php -r 'foreach(file("/proc/mounts") as $line) if(strpos($line," /tmp ")!==false) echo $line;'
mkdir /tmp/mysqli
 tar -xJf /usr/src/php.tar.xz --strip-components=3 -C /tmp/mysqli php-5.6.40/ext/mysqli
cd /tmp/mysqli
phpize
./configure --with-php-config=/usr/local/bin/php-config --with-mysqli=mysqlnd
make -j1
cp modules/mysqli.so /output/mysqli.so
php -d extension=/output/mysqli.so -r 'echo json_encode(array("php"=>PHP_VERSION,"mysqli"=>extension_loaded("mysqli"),"mysqlnd"=>extension_loaded("mysqlnd"),"client"=>mysqli_get_client_info()))."\n";'
sha256sum /output/mysqli.so
