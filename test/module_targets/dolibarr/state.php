<?php
require '/opt/dolibarr/htdocs/master.inc.php';
require_once DOL_DOCUMENT_ROOT.'/core/lib/admin.lib.php';
require_once DOL_DOCUMENT_ROOT.'/societe/class/societe.class.php';
require_once DOL_DOCUMENT_ROOT.'/contact/class/contact.class.php';
$actor=new User($db);
if($actor->fetch('', 'moduleadmin')<=0) {fwrite(STDERR,"Admin lookup failed\n");exit(1);}
$user=$actor;
$action=isset($argv[1])?$argv[1]:'state';
if($action==='empty') {
 $result=$db->query("SELECT rowid FROM llx_socpeople ORDER BY rowid");
 $ids=array();while($row=$db->fetch_array($result))$ids[]=$row['rowid'];
 foreach($ids as $id){$contact=new Contact($db);if($contact->fetch($id)<=0||$contact->delete()<=0)exit(1);}
}
if($action==='seed'||$action==='restore') {
$result=activateModule('modSociete');
if($result<0) {fwrite(STDERR,"Third-party activation failed\n");exit(1);}
$conf->setValues($db);
 $result=$db->query("SELECT rowid FROM llx_societe WHERE nom='Module Target Company' AND entity=1 ORDER BY rowid LIMIT 1");
 $row=$db->fetch_array($result);
 if($row){$companyId=$row['rowid'];}
 else {
  $company=new Societe($db);$company->name='Module Target Company';$company->client=1;$company->code_client='auto';$companyId=$company->create($actor);
  if($companyId<=0){fwrite(STDERR,$company->error);exit(1);}
 }
$records=array(
 array('firstname'=>'Alpha Ω','lastname'=>'Fixture "Quoted"','email'=>'alpha@example.invalid','note_public'=>"Public line one\n  line two, \"quoted\"  \n",'note_private'=>"  Private's note Ω  "),
 array('firstname'=>'Beta','lastname'=>'Fixture','email'=>'beta@example.invalid','note_public'=>'Public beta','note_private'=>'Private beta'),
 array('firstname'=>'NoEmail','lastname'=>'Fixture','email'=>'','note_public'=>'No email record','note_private'=>'Private no email')
);
$ids=array();
foreach($records as $record) {
 $contact=new Contact($db);
 $contact->socid=$companyId;
 foreach($record as $field=>$value) $contact->$field=$value;
 $id=$contact->create($actor);
 if($id<=0) {fwrite(STDERR,"Contact creation failed: ".$contact->error."\n");exit(1);}
 $ids[]=$id;
}

 if(getenv('DOLIBARR_LOOKUP_ENABLE')==='true') {
  if(activateModule('modTicket')<0)exit(1);
  if(dolibarr_set_const($db,'TICKET_CREATE_THIRD_PARTY_WITH_CONTACT_IF_NOT_EXIST','1','yesno',0,'',1)<=0)exit(1);
 }
}
$conf->setValues($db);
$result=$db->query('SELECT rowid as id,firstname,lastname,email,note_public,note_private FROM llx_socpeople ORDER BY rowid');
$rows=array();while($record=$db->fetch_array($result)){$row=array();foreach(array('id','firstname','lastname','email','note_public','note_private') as $key)$row[$key]=$record[$key];$rows[]=$row;}
echo json_encode(array('version'=>DOL_VERSION,'php'=>PHP_VERSION,'mysqli'=>extension_loaded('mysqli'),'admin_id'=>$actor->id,'ticket_enabled'=>!empty($conf->ticket->enabled),'lookup_enabled'=>!empty($conf->global->TICKET_CREATE_THIRD_PARTY_WITH_CONTACT_IF_NOT_EXIST),'contacts'=>$rows))."\n";
