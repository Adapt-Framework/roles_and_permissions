<?php

namespace extensions\users;
use \frameworks\adapt as adapt;

/* Prevent direct access */
defined('ADAPT_STARTED') or die;

$adapt = $GLOBALS['adapt'];

/*
 * We need to load the permissions
 */
$sql = $adapt->data_source->sql;
$sql->select('*')
    ->from('permission')
    ->where(
        new \frameworks\adapt\sql_condition(new\frameworks\adapt\sql('date_deleted'), 'is', new \frameworks\adapt\sql('null'))
    );

$results = $sql->execute()->results();

foreach($results as $result){
    define($result['php_key'], $result['permission_id'], true);
}


/*
 * Extend model_user and add has_permission()
 */
\extensions\users\model_user::extend('has_permission', function($_this, $permissions, $type = "all"){
    if ($_this->session->is_logged_in){
        
        if (!is_array($permissions)) $permissions = array($permissions);
        
        $user_permissions = $_this->store('user.permissions');
        $key = 'user_id-' . $_this->session->user->user_id;
        if (!is_array($user_permissions) || !isset($user_permissions[$key])){
            $user_permissions = array($key => array());
            
            /* Load the user's permissions */
            $sql = $_this->data_source->sql;
            $sql->select('rp.permission_id')
                ->from('role_user', 'ru')
                ->join('role_permission', 'rp', new \frameworks\adapt\sql_condition(new \frameworks\adapt\sql('ru.role_id'), '=', new \frameworks\adapt\sql('rp.role_id')))
                ->where(
                    new \frameworks\adapt\sql_and(
                        new \frameworks\adapt\sql_condition(new \frameworks\adapt\sql('ru.user_id'), '=', $_this->session->user->user_id),
                        new \frameworks\adapt\sql_condition(new \frameworks\adapt\sql('ru.date_deleted'), 'is', new \frameworks\adapt\sql('null')),
                        new \frameworks\adapt\sql_condition(new \frameworks\adapt\sql('rp.date_deleted'), 'is', new \frameworks\adapt\sql('null'))
                    )
                );
            
            $results = $sql->execute()->results();
            
            foreach($results as $result){
                $user_permissions[$key][] = $result['permission_id'];
            }
            
            $_this->store('user.permissions', $user_permissions);
        }
        
        /* Lets check if the user is authorised */
        switch(strtolower($type)){
        case "any":
            foreach($permissions as $permission){
                if (in_array($permission, $user_permissions[$key])){
                    return true;
                }
            }
            break;
        case "all":
        default:
            $match_count = 0;
            foreach($permissions as $permission){
                if (in_array($permission, $user_permissions[$key])){
                    $match_count++;
                }
            }
            if ($match_count == count($permissions)) return true;
            break;
        }
        
    }
    
    return false;
});

/* Add a new action to set the group on joining */
\application\controller_root::extend('action_set_role', function($_this){
    $role_name = $_this->setting('roles_and_permissions.default_role');
    $model = new model_role($role_name);
    if ($model->is_loaded && $_this->session->is_logged_in){
        $role_user = new model_role_user();
        $role_user->role_id = $model->role_id;
        $role_user->user_id = $_this->session->user->user_id;
        $role_user->save();
    }
});



?>