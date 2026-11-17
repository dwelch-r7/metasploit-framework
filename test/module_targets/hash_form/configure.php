<?php
$_SERVER['REQUEST_METHOD']='GET';$_SERVER['HTTP_HOST']='module-target.test';$_SERVER['SERVER_SOFTWARE']='Apache';$_SERVER['REQUEST_URI']='/';
require getcwd().'/wp-load.php';require_once ABSPATH.'wp-admin/includes/plugin.php';
if(!is_plugin_active('hash-form/hash-form.php')||!class_exists('HashFormBuilder')){throw new RuntimeException('Native Hash Form prerequisites absent');}
wp_set_current_user(get_user_by('login','module_admin')->ID);
$form=HashFormBuilder::create(['name'=>'Native Hash Form','description'=>'Owned native upload control']);
if((int)$form!==1){throw new RuntimeException('Native first form must have ID1');}
$field=HashFormFields::create_row(HashFormFields::setup_new_field_vars('upload',$form));
if(!$field||HashFormFields::get_field_vars($field)->type!=='upload'){throw new RuntimeException('Native upload field creation failed');}
$page=wp_insert_post(['post_type'=>'page','post_title'=>'Native Hash Form','post_name'=>'native-hash-form','post_content'=>'[hashform id="'.$form.'"]','post_status'=>'publish','post_author'=>1],true);
if(is_wp_error($page)){throw new RuntimeException($page->get_error_message());}
file_put_contents('/tmp/module-target-hash-ready',"ready\n");
echo json_encode(['ready'=>true,'version'=>HASHFORM_VERSION,'form'=>(int)$form,'field'=>(int)$field,'page'=>$page],JSON_THROW_ON_ERROR),PHP_EOL;
