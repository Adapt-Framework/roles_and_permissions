<?php

/* Prevent Direct Access */
defined('ADAPT_STARTED') or die;

$adapt = $GLOBALS['adapt'];
$sql = $adapt->data_source->sql;

/* Create the tables */
$sql->create_table('user_password_history')
    ->add('user_password_history_id', 'bigint')
    ->add('user_id', 'bigint')
    ->add('password', 'varchar(64)')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('user_password_history_id')
    ->foreign_key('user_id', 'user', 'user_id')
    ->execute();

$sql->create_table('role')
    ->add('role_id', 'bigint')
    ->add('bundle_name', 'varchar(128)')
    ->add('name', 'varchar(64)')
    ->add('description', 'text')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('role_id')
    ->execute();

$sql->create_table('role_user')
    ->add('role_user_id', 'bigint')
    ->add('role_id', 'bigint')
    ->add('user_id', 'bigint')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('role_user_id')
    ->foreign_key('role_id', 'role', 'role_id')
    ->foreign_key('user_id', 'user', 'user_id')
    ->execute();

$sql->create_table('permission_category')
    ->add('permission_category_id', 'bigint')
    ->add('bundle_name', 'varchar(128)', false)
    ->add('name', 'varchar(128)', false)
    ->add('description', 'text')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('permission_category_id')
    ->execute();

$sql->create_table('permission')
    ->add('permission_id', 'bigint')
    ->add('bundle_name', 'varchar(128)', false)
    ->add('name', 'varchar(64)', false)
    ->add('description', 'text')
    ->add('php_key', 'varchar(128)')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('permission_id')
    ->execute();

$sql->create_table('role_permission')
    ->add('role_permission_id', 'bigint')
    ->add('role_id', 'bigint')
    ->add('permission_id', 'bigint')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('role_permission_id')
    ->foreign_key('role_id', 'role', 'role_id')
    ->foreign_key('permission_id', 'permission', 'permission_id')
    ->execute();

$sql->create_table('password_policy')
    ->add('password_policy_id', 'bigint')
    ->add('allow_password_change', "enum('Yes', 'No')", false, 'Yes')
    ->add('min_length', 'int')
    ->add('max_length', 'int')
    ->add('mixed_case', "enum('Yes', 'No')", false, 'No')
    ->add('include_alpha', "enum('Yes', 'No')", false,'Yes')
    ->add('include_numeric', "enum('Yes', 'No')", false,'Yes')
    ->add('include_symbols', "enum('Yes', 'No')", false,'No')
    ->add('password_history', 'int', false, 0)
    ->add('can_change_password_after_days', 'int', false, 0)
    ->add('must_change_password_after_days', 'int')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('password_policy_id')
    ->execute();

$sql->create_table('role_password_policy_id')
    ->add('role_password_policy_id', 'bigint')
    ->add('role_id', 'bigint')
    ->add('password_policy_id', 'bigint')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('role_password_policy_id')
    ->foreign_key('role_id', 'role', 'role_id')
    ->foreign_key('password_policy_id')
    ->execute();
    
    
?>