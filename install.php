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
    //->add('show', 'enum("Yes", "No")', true, 'Yes') //Should it be displayed in the administator?
    ->add('name', 'varchar(128)', false)
    ->add('label', 'varchar(128)', false)
    ->add('description', 'text')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('permission_category_id')
    ->execute();

$sql->create_table('permission')
    ->add('permission_id', 'bigint')
    ->add('permission_category_id', 'bigint')
    ->add('bundle_name', 'varchar(128)', false)
    ->add('name', 'varchar(64)', false)
    ->add('label', 'varchar(64)')
    ->add('description', 'text')
    ->add('php_key', 'varchar(128)')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('permission_id')
    ->foreign_key('permission_category_id', 'permission_category', 'permission_category_id')
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

$sql->create_table('role_password_policy')
    ->add('role_password_policy_id', 'bigint')
    ->add('role_id', 'bigint')
    ->add('password_policy_id', 'bigint')
    ->add('date_created', 'datetime')
    ->add('date_modified', 'timestamp')
    ->add('date_deleted', 'datetime')
    ->primary_key('role_password_policy_id')
    ->foreign_key('role_id', 'role', 'role_id')
    ->foreign_key('password_policy_id', 'password_policy', 'password_policy_id')
    ->execute();

/*
 * Add roles
 */
$role = new model_role();
$role->bundle_name = 'roles_and_permissions';
$role->name = 'User';
$role->description = 'General user accounts.';
$role->save();


/*
 * Add permission categories
 */
$cat = new model_permission_category();
$cat->bundle_name = 'roles_and_permissions';
$cat->name = 'general';
$cat->label = 'General';
$cat->save();

$permission = new model_permission();
$permission->permission_category_id = $cat->permission_category_id;
$permission->bundle_name = 'roles_and_permissions';
$permission->name = 'can_change_password';
$permission->label = 'Can change password';
$permission->description = 'Allows the user to change there password whenever they choose.';
$permission->php_key = 'PERM_CAN_CHANGE_PASSWORD';
$permission->save();

$change_password_permission = $permission->permission_id;

$permission = new model_permission();
$permission->permission_category_id = $cat->permission_category_id;
$permission->bundle_name = 'roles_and_permissions';
$permission->name = 'can_login';
$permission->label = 'Can login';
$permission->description = 'Allows the user to login to the site.';
$permission->php_key = 'PERM_CAN_LOGIN';
$permission->save();

$login_permission = $permission->permission_id;

/*
 * Add permissions to the user role
 */
$role_permission = new model_role_permission();
$role_permission->role_id = $role->role_id;
$role_permission->permission_id = $login_permission;
$role_permission->save();

$role_permission = new model_role_permission();
$role_permission->role_id = $role->role_id;
$role_permission->permission_id = $change_password_permission;
$role_permission->save();

/*
 * Update the user join forms and add the set_role
 * action to them
 */
$form = new model_form('join_email');
if ($form->is_loaded){
    $form->actions = $form->actions . "," . "set-role";
}
$form->save();

$form = new model_form('join_username');
if ($form->is_loaded){
    $form->actions = $form->actions . "," . "set-role";
}
$form->save();

?>