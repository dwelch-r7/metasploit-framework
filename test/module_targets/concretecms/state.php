<?php
chdir('/app');
define('C5_EXECUTE', true);
define('DIR_BASE', '/app');
define('C5_ENVIRONMENT_ONLY', true);
require '/app/concrete/bootstrap/configure.php';
require '/app/concrete/bootstrap/autoload.php';
$app = require '/app/concrete/bootstrap/start.php';
$db = $app->make('database')->connection();
$actor = \Concrete\Core\User\User::getByUserID(1);
if (!$actor || !$actor->isSuperUser()) {throw new RuntimeException('Expected fixture administrator');}
$app->instance(\Concrete\Core\User\User::class, $actor);
$marker = '/tmp/module-target-seed.json';
$action = $argv[1] ?? 'state';
if ($action === 'seed' && !is_file($marker)) {
    $root = \Concrete\Core\Page\Page::getByID(1);
    $importer = $app->make(\Concrete\Core\File\Import\FileImporter::class);
    $files = [];
    foreach (['public', 'unused', 'private'] as $index=>$name) {
        $image = imagecreatetruecolor(2,2);
        imagefill($image,0,0,imagecolorallocate($image,40+$index,80,120));
        $path = '/tmp/module-target-'.$name.'.png';
        imagepng($image,$path);imagedestroy($image);
        $version = $importer->importLocalFile($path,'module-target-'.$name.'.png');
        $files[$name] = $version->getFileID();
    }
    $template = \Concrete\Core\Page\Template::getByHandle('full');
    $public = $root->add(null,['cName'=>'Module public, "quoted" Ω','cHandle'=>'module-target-public','uID'=>1],$template);
    $private = $root->add(null,['cName'=>'Module private Ω','cHandle'=>'module-target-private-Ω','uID'=>1,'cIsActive'=>0,'cIsDraft'=>1],$template);
    $private->setPermissionsToOverride();
    $private->removePermissions(\Concrete\Core\User\Group\Group::getByID(GUEST_GROUP_ID),['view_page']);
    $blockType = \Concrete\Core\Block\BlockType\BlockType::getByHandle('image');
    $public->addBlock($blockType,'Main',['fID'=>$files['public'],'altText'=>'Public fixture image']);
    $public->addBlock($blockType,'Main',['fID'=>$files['public'],'altText'=>'Repeated public fixture image']);
    $private->addBlock($blockType,'Main',['fID'=>$files['public'],'altText'=>'Private fixture image']);
    $private->addBlock($blockType,'Main',['fID'=>$files['private'],'altText'=>'Private-only fixture image']);
    $tracker = $app->make(\Concrete\Core\File\Tracker\UsageTracker::class);
    $tracker->track($public);$tracker->track($private);
    $newVersion = $public->getVersionObject()->createNew('Second fixture version');
    $public = \Concrete\Core\Page\Page::getByID($public->getCollectionID(),$newVersion->getVersionID());
    $tracker->track($public);
    file_put_contents($marker,json_encode(['files'=>$files,'pages'=>['public'=>$public->getCollectionID(),'private'=>$private->getCollectionID()]]));
}
$seed = is_file($marker) ? json_decode(file_get_contents($marker),true) : null;
$pages = [];
if ($seed) foreach ($seed['pages'] as $name=>$id) {
    $page = \Concrete\Core\Page\Page::getByID($id,'RECENT');
    $pages[$name] = ['id'=>$page->getCollectionID(),'version'=>$page->getVersionID(),'handle'=>$page->getCollectionHandle(),'path'=>$page->getCollectionPath(),'active'=>$page->isActive(),'draft'=>$page->isPageDraft()];
}
$usage = $db->fetchAllAssociative('SELECT * FROM FileUsageRecord ORDER BY file_id,collection_id,collection_version_id,block_id');
$expected = [];
foreach ($usage as $record) {
    $page = \Concrete\Core\Page\Page::getByID($record['collection_id'],'RECENT');
    $expected[$record['file_id']][$record['collection_id']] = [(string)$record['file_id'],(string)$page->getCollectionID(),(string)$page->getVersionID(),(string)$page->getCollectionHandle(),$page->getCollectionPath() ?: '/'];
}
foreach($expected as $fileId=>$rows)$expected[$fileId]=array_values($rows);
echo json_encode(['version'=>$app->make('config')->get('concrete.version'),'seed'=>$seed,'pages'=>$pages,'usage'=>$usage,'expected_usage'=>$expected,'file_count'=>$db->fetchOne('SELECT COUNT(*) FROM Files')],JSON_PRETTY_PRINT)."\n";
