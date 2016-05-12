<?php

namespace adapt\users\roles_and_permissions{
    
    /* Prevent Direct Access */
    defined('ADAPT_STARTED') or die;
    
    class bundle_roles_and_permissions extends \adapt\bundle{
        
        public function __construct($data){
            parent::__construct('roles_and_permissions', $data);
        }
        
        public function boot(){
            if (parent::boot()){
                
                $this->dom->head->add(new html_script(array('type' => 'text/javascript', 'src' => "/adapt/roles_and_permissions/roles_and_permissions-{$this->version}/static/js/roles_and_permissions.js")));
                
                
                $sql = $this->data_source->sql;
                $sql->select('*')
                    ->from('permission')
                    ->where(
                        new sql_cond('date_deleted', sql::IS, new sql_null)
                    );
                
                $results = $sql->execute()->results();
                
                foreach($results as $result){
                    define($result['php_key'], $result['permission_id'], true);
                }
                
                /*
                 * Extend model_user and add has_permission()
                 */
                \adapt\users\model_user::extend('has_permission', function($_this, $permissions, $type = "all"){
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
                                ->join('role_permission', 'rp', new \adapt\sql_condition(new \adapt\sql('ru.role_id'), '=', new \adapt\sql('rp.role_id')))
                                ->where(
                                    new \adapt\sql_and(
                                        new \adapt\sql_condition(new \adapt\sql('ru.user_id'), '=', $_this->session->user->user_id),
                                        new \adapt\sql_condition(new \adapt\sql('ru.date_deleted'), 'is', new \adapt\sql('null')),
                                        new \adapt\sql_condition(new \adapt\sql('rp.date_deleted'), 'is', new \adapt\sql('null'))
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
                
                \adapt\users\model_user::extend('pget_password_policy', function($_this){
                    if ($_this->is_loaded){
                        $children = $_this->get();
                        foreach($children as $child){
                            if ($child instanceof \adapt\model && $child->table_name == "password_policy"){
                                return $child;
                            }
                        }
                        
                        //print "<pre>" . $_this
                        //    ->data_source
                        //    ->sql
                        //    ->select('pp.*')
                        //    ->from('password_policy', 'pp')
                        //    ->join('role_password_policy', 'rpp', 'password_policy_id')
                        //    ->join('role_user', 'ru', 'role_id')
                        //    ->where(
                        //        new sql_and(
                        //            new sql_cond('ru.user_id', sql::EQUALS, sql::q($_this->user_id)),
                        //            new sql_cond('ru.date_deleted', sql::IS, new sql_null()),
                        //            new sql_cond('rpp.date_deleted', sql::IS, new sql_null()),
                        //            new sql_cond('pp.date_deleted', sql::IS, new sql_null())
                        //        )
                        //    )
                        //    ->order_by('pp.priority')
                        //    ->limit(1) . "</pre>";
                        
                        $results = $_this
                            ->data_source
                            ->sql
                            ->select('pp.*')
                            ->from('password_policy', 'pp')
                            ->join('role_password_policy', 'rpp', 'password_policy_id')
                            ->join('role_user', 'ru', 'role_id')
                            ->where(
                                new sql_and(
                                    new sql_cond('ru.user_id', sql::EQUALS, sql::q($_this->user_id)),
                                    new sql_cond('ru.date_deleted', sql::IS, new sql_null()),
                                    new sql_cond('rpp.date_deleted', sql::IS, new sql_null()),
                                    new sql_cond('pp.date_deleted', sql::IS, new sql_null())
                                )
                            )
                            ->order_by('pp.priority')
                            ->limit(1)
                            ->execute(0)
                            ->results();
                        
                        if (is_array($results) && count($results) == 1){
                            $policy = new model_password_policy();
                            if ($policy->load_by_data($results[0])){
                                $_this->add($policy);
                                return $policy;
                            }
                            
                        }
                    }
                    
                    return null;
                });
                
                \adapt\users\model_user::extend('pget_can_change_password', function($_this){
                    $policy = $_this->password_policy;
                    if ($policy instanceof \adapt\model){
                        if ($policy->allow_password_change == "No"){
                            return false;
                        }
                        
                        $date_last_changed = $_this->date_password_changed;
                        
                        if ($policy->can_change_password_after_days && $date_last_changed){
                            $date = new \adapt\date($date_last_changed);
                            $date->goto_days($policy->can_change_password_after_days);
                            
                            if ($date->is_future()){
                                return false;
                            }
                        }
                        
                        
                    }
                    
                    return true;
                });
                
                \adapt\users\model_user::extend('pget_must_change_password', function($_this){
                    $policy = $_this->password_policy;
                    if ($policy instanceof \adapt\model){
                        if ($policy->allow_password_change == "No"){
                            return false;
                        }
                        
                        $date_last_changed = $_this->date_password_changed;
                        
                        if ($policy->must_change_password_after_days && $date_last_changed){
                            $date = new \adapt\date($date_last_changed);
                            $date->goto_days($policy->must_change_password_after_days);
                            
                            if ($date->is_past()){
                                return true;
                            }
                        }
                        
                        
                    }
                    
                    return false;
                });
                
                \adapt\users\model_user::extend('pget_date_password_changed', function($_this){
                    if ($_this->is_loaded){
                        $results = $_this
                            ->data_source
                            ->sql
                            ->select('date_created')
                            ->from('user_password_history')
                            ->where(
                                new sql_and(
                                    new sql_cond('user_id', sql::EQUALS, sql::q($_this->user_id)),
                                    new sql_cond('date_deleted', sql::IS, new sql_null())
                                )
                            )
                            ->order_by('date_created', false)
                            ->limit(1)
                            ->execute()
                            ->results();
                        
                        if (is_array($results) && count($results) == 1){
                            return $results[0]['date_created'];
                        }
                    }
                    
                    return null;
                });
                
                /* Override the password property on the user object */
                \adapt\users\model_user::extend('change_password', function($_this, $new_password){
                    if ($_this->is_loaded){
                        $policy = $_this->password_policy;
                        if ($policy instanceof \adapt\model){
                            if ($policy->allow_password_change == "No"){
                                $_this->error("You cannot change your password.");
                                return false;
                            }
                            
                            if ($policy->can_change_password_after_days){
                                $date_last_changed = $_this->date_password_changed;
                                
                                if ($policy->can_change_password_after_days && $date_last_changed){
                                    $date = new \adapt\date($date_last_changed);
                                    $date->goto_days($policy->can_change_password_after_days);
                                    
                                    if ($date->is_future()){
                                        $_this->error("You cannot change your password at this time.");
                                        return false;
                                    }
                                }
                            }
                            
                            if ($policy->min_length && strlen($new_password) < $policy->min_length){
                                $_this->error("The password is too short, passwords must be at least {$policy->min_length} characters long.");
                                return false;
                            }
                            
                            if ($policy->max_length && strlen($new_password) > $policy->max_length){
                                $_this->error("The password is too long, passwords must be a maximum {$policy->max_length} characters long.");
                                return false;
                            }
                            
                            if ($policy->mixed_case == "Yes"){
                                if (!preg_match("/[A-Z]/", $new_password)){
                                    $_this->error("The password must contain at least one upper case character.");
                                    return false;
                                }
                                
                                if (!preg_match("/[a-z]/", $new_password)){
                                    $_this->error("The password must contain at least one lower case character.");
                                    return false;
                                }
                            }
                            
                            if ($policy->include_alpha == "Yes"){
                                if (!preg_match("/[a-zA-Z]/", $new_password)){
                                    $_this->error("The password must contain at least one character from A - Z.");
                                    return false;
                                }
                            }
                            
                            if ($policy->include_numeric == "Yes"){
                                if (!preg_match("/[0-9]/", $new_password)){
                                    $_this->error("The password must contain at least one number.");
                                    return false;
                                }
                            }
                            
                            if ($policy->include_symbols == "Yes"){
                                if (!preg_match("/[-!$%^&*()_+|~=`{}\[\]:\";'<>?,.\/]/", $new_password)){
                                    $_this->error("The password must contain at least one symbol.");
                                    return false;
                                }
                            }
                            
                            if ($policy->password_history){
                                /* Get the previous passwords */
                                $results = $_this
                                    ->data_source
                                    ->sql
                                    ->select('password')
                                    ->from('user_password_history')
                                    ->where(
                                        new sql_and(
                                            new sql_cond('user_id', sql::EQUALS, sql::q($_this->user_id)),
                                            new sql_cond('date_deleted', sql::IS, new sql_null())
                                        )
                                    )
                                    ->order_by('date_created', false)
                                    ->limit($policy->password_history)
                                    ->execute(0)
                                    ->results();
                                
                                if (is_array($results)){
                                    
                                    foreach($results as $result){
                                        list($salt, $password) = explode(":", $result['password']);
                                        
                                        $hashed_password = \adapt\users\model_user::hash_password($new_password, $salt);
                                        
                                        if ($hashed_password == $result['password']){
                                            $_this->error("The new password cannot be the same as your previous {$policy->password_history} passwords.");
                                            return false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    $_this->password = $new_password;
                    
                    /* Record it in the password history */
                    $history = new model_user_password_history();
                    $history->password = $_this->password;
                    $_this->add($history);
                    
                    return true;
                });
                
                /*
                 * Override the user bundle to handle password changes
                 */
                \application\controller_root::extend('view_change_password', function($_this){
                    if ($_this->session->is_logged_in){
                        
                        /*
                         * Is the user a member of any groups with policies?
                         */
                        $results = $_this
                            ->data_source
                            ->sql
                            ->select('pp.*')
                            ->from('password_policy', 'pp')
                            ->join('role_password_policy', 'rpp', 'password_policy_id')
                            ->join('role_user', 'ru', 'role_id')
                            ->where(
                                new sql_and(
                                    new sql_cond('ru.user_id', sql::EQUALS, sql::q($_this->session->user->user_id)),
                                    new sql_cond('ru.date_deleted', sql::IS, new sql_null()),
                                    new sql_cond('rpp.date_deleted', sql::IS, new sql_null()),
                                    new sql_cond('pp.date_deleted', sql::IS, new sql_null())
                                )
                            )
                            ->order_by('pp.priority')
                            ->limit(1)
                            ->execute()
                            ->results();
                        
                        if (is_array($results) && count($results) == 1){
                            $policy = new model_password_policy();
                            if ($policy->load_by_data($results[0])){
                                $_this->add_view(new \adapt\users\roles_and_permissions\view_password_change($policy));
                            }else{
                                $_this->add_view(new \adapt\users\view_password_change());
                            }
                            
                        }else{
                            $_this->add_view(new \adapt\users\view_password_change());
                        }
                        
                        
                    }else{
                        $_this->redirect("/");
                    }
                });
                
                \application\controller_root::extend('view_reset_password', function($_this){
                    //if (isset($_this->request['token'])){
                    //    $_this->add_view(new \adapt\users\view_password_change(false, $_this->request));
                    //}else{
                    //    $_this->add_view(new \adapt\users\view_invalid_token());
                    //}
                    if ($_this->session->is_logged_in){
                        
                        /*
                         * Is the user a member of any groups with policies?
                         */
                        $results = $_this
                            ->data_source
                            ->sql
                            ->select('pp.*')
                            ->from('password_policy', 'pp')
                            ->join('role_password_policy', 'rpp', 'password_policy_id')
                            ->join('role_user', 'ru', 'role_id')
                            ->where(
                                new sql_and(
                                    new sql_cond('ru.user_id', sql::EQUALS, sql::q($_this->session->user->user_id)),
                                    new sql_cond('ru.date_deleted', sql::IS, new sql_null()),
                                    new sql_cond('rpp.date_deleted', sql::IS, new sql_null()),
                                    new sql_cond('pp.date_deleted', sql::IS, new sql_null())
                                )
                            )
                            ->order_by('pp.priority')
                            ->limit(1)
                            ->execute()
                            ->results();
                        
                        if (is_array($results) && count($results) == 1){
                            $policy = new model_password_policy();
                            if ($policy->load_by_data($results[0])){
                                $_this->add_view(new \adapt\users\roles_and_permissions\view_password_change($policy, false));
                            }else{
                                $_this->add_view(new \adapt\users\view_password_change(false));
                            }
                            
                        }else{
                            $_this->add_view(new \adapt\users\view_password_change(false));
                        }
                        
                        
                    }else{
                        $_this->redirect("/");
                    }
                });
                
                \application\controller_root::extend('action_change_password', function($_this){
                    if ($_this->session->is_logged_in){
                        $password = $_this->request['current_password'];
                        $new_password = $_this->request['new_password'];
                        
                        /* Check against previous password */
                        $current_password_raw = $_this->session->user->password;
                        list($salt, $current_password) = explode(":", $current_password_raw);
                        
                        $hashed_password = model_user::hash_password($password, $salt);
                        
                        if ($hashed_password == $current_password_raw){
                            //$_this->session->user->password = $new_password;
                            $_this->session->user->change_password($new_password);
                            if (!$_this->session->user->save()){
                                $_this->respond('change_password_with_policy', array('errors' => $_this->session->user->errors(true)));
                                $_this->redirect("/change-password");
                                return;
                            }
                        }else{
                            $_this->respond('change_password_with_policy', array('errors' => array("Your current password was incorrect, please try again.")));
                            $_this->redirect("/change-password");
                            return;
                        }
                        
                        $_this->redirect("/password-changed");
                        return;
                    }
                    
                    $_this->redirect("/");
                });
                
                \application\controller_root::extend('action_set_new_password', function($_this){
                    if ($_this->session->is_logged_in){
                        if ($_this->request['token']){
                            
                            /* Lets check the token is valid, we are going to do this at sql
                             * level because we do not want to change the access count or
                             * invalidate the token in anyway.
                             */
                            $sql = $_this->data_source->sql;
                            
                            $sql->select('*')
                                ->from('user_login_token')
                                ->where(
                                    new sql_and(
                                        new sql_cond('token', sql::EQUALS, sql::q($_this->request['token'])),
                                        new sql_cond('user_id', sql::EQUALS, sql::q($_this->session->user->user_id)),
                                        new sql_cond('token_type', sql::EQUALS, sql::q("Password reset")),
                                        new sql_cond('date_deleted', sql::IS, new sql_null())
                                    )
                                );
                            
                            $sql->execute(0); //Ensure the result is not from the cache
                            
                            /* Get the results */
                            $results = $sql->results();
                            
                            if (count($results) == 1){
                                /* Success */
                                //$_this->session->user->password = $_this->request['new_password'];
                                $_this->session->user->change_password($_this->request['new_password']);
                                if (!$_this->session->user->save()){
                                    $_this->respond('change_password_with_policy', array('errors' => $_this->session->user->errors(true)));
                                    $_this->redirect("/reset-password?token=" . $_this->request['token']);
                                    return;
                                }else{
                                    $_this->redirect("/password-changed");
                                }
                                
                            }else{
                                $_this->respond('change_password_with_policy', array('errors' => array("We were unable to change your password at this time, please try again.")));
                                $_this->redirect("/change-password"); //Because we do not have a token
                            }
                            
                        }else{
                            $_this->respond('change_password_with_policy', array('errors' => array("We were unable to change your password at this time, please try again.")));
                            $_this->redirect("/change-password"); //Because we do not have a token
                        }
                    }
                    
                });
                
                /* We need to seek out the action join and append the action set_role */
                if (preg_match("/\bjoin\b/", $this->request['actions'])){
                    $this->request('actions', $this->request['actions'] . ",set-role");
                }
                
                /* Enforce password change when must_change_password_after comes into effect */
                if ($this->session->user->must_change_password){
                    if (!preg_match("/change-password/", $this->request['url']) && !preg_match("/change-password/", $this->request['actions']) && $this->session->is_logged_in && $this->session->user->password_change_required == "Yes"){
                        $this->redirect("/change-password");
                    }
                }
                
                return true;
            }
            
            return false;
        }
        
    }
    
    
}

?>