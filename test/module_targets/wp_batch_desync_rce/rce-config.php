<?php
if (getenv('LAB_UPLOADS_DISABLED') === '1') {
    define('DISALLOW_FILE_MODS', true);
}
