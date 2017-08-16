<?php

namespace adapt\users\roles_and_permissions{
    
    /* Prevent Direct Access */
    defined('ADAPT_STARTED') or die;
    
    class bundle_roles_and_permissions extends \adapt\bundle{
        
    protected $_roles;
    protected $_password_policies;


    public function __construct($data){
            parent::__construct('roles_and_permissions', $data);
            
            $this->_roles = [];
            $this->_password_policies = [];
            
            $this->register_config_handler('roles_and_permissions', 'roles', 'process_roles_tag');
            $this->register_config_handler('roles_and_permissions', 'password_policies', 'process_password_policies_tag');
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
                
                /* Extend the user an derive the permission level */
                \adapt\users\model_user::extend(
                    'mget_permission_level',
                    function($_this){
                        if (!$_this->is_loaded){
                            return 0;
                        }
                        
                        $local_cache_key = "roles_and_permission.permission_level.user{$_this->user_id}";
                        $permission_level = $_this->store($local_cache_key);
                        
                        if (!is_null($permission_level)){
                            return $permission_level;
                        }
                        
                        $sql = $_this->data_source->sql;
                        
                        $sql->select('max(p.permission_level) as permission_level')
                            ->from('role_user', 'ru')
                            ->join('role', 'r',
                                new sql_and(
                                    new sql_cond('r.date_deleted', sql::IS, sql::NULL),
                                    new sql_cond('r.role_id', sql::EQUALS, 'ru.role_id'),
                                    new sql_cond('ru.user_id', sql::EQUALS, q($_this->user_id))
                                )
                            )
                            ->join('role_permission', 'rp',
                                new sql_and(
                                    new sql_cond('rp.date_deleted', sql::IS, sql::NULL),
                                    new sql_cond('rp.role_id', sql::EQUALS, 'r.role_id')
                                )
                            )
                            ->join('permission', 'p',
                                new sql_and(
                                    new sql_cond('p.date_deleted', sql::IS, sql::NULL),
                                    new sql_cond('p.permission_id', sql::EQUALS, 'rp.permission_id')
                                )
                            )
                            ->where(
                                new sql_and(
                                    new sql_cond('ru.date_deleted', sql::IS, sql::NULL)
                                )
                            );
                        
                        $results = $sql->execute()->results();
                        $permission_level = 0;
                        if (count($results) == 1){
                            $permission_level = $results[0]['permission_level'];
                        }
                        
                        $_this->store($local_cache_key, $permission_level);
                        
                        return $permission_level;
                    }
                );
                
                /* Add a new action to set the group on joining */
                \adapt\users\model_user::extend('set_role',
                    function($_this, $role_name){
                        /* Check the user doesn't already have the role */
                        if (!$_this->has_role($role_name)){
                            $role = new model_role();
                            if (!$role->load_by_name($role_name)){
                                $_this->error("Unknown role named '{$role_name}'");
                                return false;
                            }
                            
                            if ($role->highest_level > $_this->session->user->permission_level){
                                $_this->error("You are not permitted to assign this role to other users");
                                return false;
                            }
                            
                            $role_user = new model_role_user();
                            $role_user->role_id = $role->role_id;
                            if ($_this->is_loaded){
                                $role_user->user_id = $_this->user_id;
                                return $role_user->save();
                            }else{
                                $_this->add($role_user);
                                return true;
                            }
                            
                        }
                        
                    }
                );
                
                \adapt\users\model_user::extend('remove_role',
                    function ($_this, $role_name){
                        if ($_this->has_role($role_name)){
                            $role = new model_role();
                            if (!$role->load_by_name($role_name)){
                                $this->error('Unable to find role');
                                return false;
                            }
                            
                            $children = $_this->get();
                            foreach($children as $child){
                                if ($child instanceof \adapt\model && $child->table_name == "role_user" && $child->role_id == $role->role_id){
                                    $child->delete();
                                }
                            }
                            
                            return true;
                        }
                        
                        $this->error('Role not found for this user');
                        return false;
                    }
                );
                
                \adapt\users\model_user::extend('has_role',
                    function($_this, $role){
                        if ($_this->is_loaded){
                            $sql = $_this->data_source->sql;
                            $sql->select('role_id')
                                ->from('role_user')
                                ->where(
                                    new sql_cond('user_id', sql::EQUALS, $_this->user_id),
                                    new sql_cond('date_delete', sql::IS, sql::NULL)
                                );
                            $results = $sql->execute(0)->results();
                            
                            if (count($results)){
                                return true;
                            }
                            
                            return false;
                        }
                        
                    }
                );
                
//                \application\controller_root::extend('action_set_role', function($_this){
//                    $role_name = $_this->setting('roles_and_permissions.default_role');
//                    $model = new model_role($role_name);
//                    if ($model->is_loaded && $_this->session->is_logged_in){
//                        $role_user = new model_role_user();
//                        $role_user->role_id = $model->role_id;
//                        $role_user->user_id = $_this->session->user->user_id;
//                        $role_user->save();
//                    }
//                });
                
                \adapt\users\model_user::extend('pget_password_policy', function($_this){
                    if ($_this->is_loaded){
                        $children = $_this->get();
                        foreach($children as $child){
                            if ($child instanceof \adapt\model && $child->table_name == "password_policy"){
                                return $child;
                            }
                        }
                        
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
                \adapt\users\model_user::extend('change_password', function($_this, $new_password, $policy_id = null){
                    if ($_this->is_loaded || $policy_id !== null){
                        $policy = $_this->password_policy;

                        if ($policy === null && $policy_id) {
                            $policy = new model_password_policy($policy_id);
                        }

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
                                if (!preg_match("/[-@!£#$%^&*()_+|~=`{}\[\]:\";'<>?,.\/]/", $new_password)){
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
					if (password_verify($new_password, $result['password'])){
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
                
//                \adapt\users\model_user::extend('mget_permission_level',
//                    function($_this){
//                        $sql = $_this->data_source->sql;
//                        $sql->select('max(p.permission_level)')
//                            ->from('role_user', 'ru')
//                            ->join('role', 'r', new sql_and(
//                                new sql_cond('r.role_id', sql::EQUALS, 'ru.role_id'),
//                                new sql_cond('r.date_deleted', sql::IS, sql::NULL)
//                            ))
//                            ->join('role_permission', 'rp', new sql_and(
//                                new sql_cond('rp.role_id', sql::EQUALS, 'r.role_id'),
//                                new sql_cond('rp.date_deleted', sql::IS, sql::NULL)
//                            ))
//                            ->join('permission', 'p', new sql_and(
//                                new sql_cond('p.permission_id', sql::EQUALS, 'rp.permission_id'),
//                                new sql_cond('p.date_deleted', sql::IS, sql::NULL)
//                            ))
//                            ->where(
//                                new sql_and(
//                                    new sql_cond('ru.user_id', sql::EQUALS, q($_this->user_id)),
//                                    new sql_cond('ru.date_deleted', sql::IS, sql::NULL)
//                                )
//                            );
//                        
//                        $results = $sql->execute(60)->results();
//                        
//                        if (!$results || !count($results)){
//                            return 0;
//                        }
//                        
//                        return array_values($results[0])[0];
//                    }
//                );
                
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
        
        public function process_password_policies_tag($bundle, $tag_data){
            if ($bundle instanceof \adapt\bundle && $tag_data instanceof \adapt\xml){
                $this->register_install_handler($this->name, $bundle->name, 'install_password_policies');
                if (!is_array($this->_password_policies)){
                    $this->_password_policies[$bundle->name] = [];
                }
                
                $password_policies = $tag_data->get();
                foreach($password_policies as $password_policy){
                    if ($password_policy instanceof \adapt\xml && $password_policy->tag == "password_policy"){
                        
                        $policy_data = [];
                        $policy_data['name'] = $password_policy->attr('name');
                        
                        $policy_children = $password_policy->get();
                        foreach($policy_children as $child){
                            if ($child instanceof \adapt\xml){
                                $policy_data[$child->tag] = $child->text;
                            }
                        }
                        
                    }
                    $this->_password_policies[$bundle->name][] = $policy_data;
                }

            }
        }
        
        public function process_roles_tag($bundle, $tag_data){
            if ($bundle instanceof \adapt\bundle && $tag_data instanceof \adapt\xml){
                $this->register_install_handler($this->name, $bundle->name, 'install_roles');
                if (!is_array($this->_roles[$bundle->name])){
                    $this->_roles[$bundle->name] = [];
                }
                
                $roles = $tag_data->get();
                foreach($roles as $role){
                    if ($role instanceof \adapt\xml && $role->tag == "role"){
                        
                        $role_data = [];
                        $role_data['name'] = $role->attr('name');
                        
                        $role_children = $role->get();
                        foreach($role_children as $role_child){
                            if ($role_child instanceof \adapt\xml){
                                switch($role_child->tag){
                                case "label":
                                    $role_data['label'] = $role_child->get(0);
                                    break;
                                case "description":
                                    $role_data['description'] = $role_child->get(0);
                                    break;
                                case "users":
                                    $role_data['users'] = [];
                                    $users_children = $role_child->get();
                                    foreach($users_children as $user){
                                        if ($user instanceof \adapt\xml && $user->tag == "username"){
                                            $role_data['users'][] = $user->get(0);
                                        }
                                    }
                                    break;
                                case "permissions":
                                    $role_data['permissions'] = [];
                                    $permissions_children = $role_child->get();
                                    foreach($permissions_children as $permission){
                                        if ($permission instanceof \adapt\xml && $permission->tag == "permission"){
                                            $role_data['permissions'][] = $permission->get(0);
                                        }
                                    }
                                    break;
                                case "password_policies":
                                    $role_data['password_policies'] = [];
                                    $policies_children = $role_child->get();
                                    foreach($policies_children as $policy_child){
                                        if ($policy_child instanceof \adapt\xml && $policy_child->tag == "password_policy"){
                                            $role_data['password_policies'][] = $policy_child->get(0);
                                        }
                                    }
                                    break;
                                default:
                                    if ($role_child->attr('get-from')){
                                        $role_data[$role_child->tag] = $role_child->attributes;
                                    }else{
                                        $role_data[$role_child->tag] = $role_child->get(0);
                                    }
                                }
                            }
                        }
                        $this->_roles[$bundle->name][] = $role_data;
                    }
                }
            }
        }
        
        public function process_user_roles_tag($bundle, $tag_data){
            if ($bundle instanceof \adapt\bundle && $tag_data instanceof \adapt\xml){
                $this->register_install_handler($this->name, $bundle->name, 'install_users_roles');
                
                $user_roles_nodes = $tag_data->get();
                $this->_roles[$bundle->name] = [];
                foreach($user_roles_nodes as $user_role_node){
                    if ($user_role_node instanceof \adapt\xml && ($user_role_node->tag == 'user_role'|| $user_role_node->tag == 'role_permission')){
                        $child_nodes = $user_role_node->get();
                        $user_roles = [];
                        foreach($child_nodes as $key => $child_node){
                            if ($child_node instanceof \adapt\xml){
                                switch($child_node->tag){
                                case "role":
                                    $user_roles['role']['role'] = $child_node->get(0);
                                    break;
                                case "username":
                                    $user_roles['role']['username'] = $child_node->get(0);
                                    break;
                                case "permission":
                                    $user_roles['permission']['permission'] = $child_node->get(0);
                                    break;
                                case "role_permission_name":
                                    $user_roles['permission']['role'] = $child_node->get(0);
                                    break;
                                
                                }
                            }
                        }
                        if (!is_array($this->_roles[$bundle->name])) $this->_roles[$bundle->name] = [];
                        $this->_roles[$bundle->name][] = $user_roles;
                    }
                }
            }                                     
        }
        
        public function install_password_policies($bundle){
            if ($bundle instanceof \adapt\bundle){
                if (is_array($this->_password_policies[$bundle->name])){
                    foreach($this->_password_policies[$bundle->name] as $policy){
                        $model = new model_password_policy();
                        if (!$model->load_by_name($policy['name'])){
                            $model->errors(true);
                            $model->bundle_name = $bundle->name;
                        }
                        
                        foreach($policy as $key => $value){
                            $model->$key = $value;
                        }
                        
                        $model->save();
                    }
                }
            }
        }
        
        public function install_roles($bundle){
            if ($bundle instanceof \adapt\bundle){
                if (is_array($this->_roles[$bundle->name])){
                    foreach($this->_roles[$bundle->name] as $role){
                        $model = new model_role();
                        $model->disable_permission_checks = true;
                        
                        if (!$model->load_by_name($role['name'])){
                            $model->errors(true);
                            $model->bundle_name = $bundle->name;
                        }
                        
                        foreach($role as $key => $value){
                            if (!is_array($value)){
                                $model->$key = $value;
                            }else{
                                if (isset($value['get-from'])){
                                    $conditions = [];
                                    foreach($value as $val_key => $val_val){
                                        $matches = [];
                                        if (preg_match("/^where\-([_A-Za-z0-9]+)\-is$/", $val_key, $matches)){
                                            $conditions[] = new sql_cond($matches[1], sql::EQUALS, q($val_val));
                                        }
                                    }
                                    
                                    if (count($conditions)){
                                        $sql = $this->data_source->sql;
                                        $sql->select($value['get-from'] . '_id')
                                            ->from($value['get-from']);
                                        if (count($conditions) == 1){
                                            $sql->where($conditions[0]);
                                        }else{
                                            $sql->where(new sql_and($conditions));
                                        }
                                        
                                        $results = $sql->execute()->results();
                                        
                                        if (count($results) && count($results) == 1){
                                            $model->$key = $results[0][$value['get-from'] . "_id"];
                                        }
                                    }
                                }elseif($key == "permissions"){
                                    foreach($value as $permission){
                                        $model->add_permission_by_name($permission);
                                    }
                                }elseif($key == "users"){
                                    foreach($value as $user){
                                        $model->add_user_by_username($user);
                                    }
                                }elseif($key == "password_policies"){
                                    foreach($value as $policy){
                                        $model->add_password_policy_by_name($policy);
                                    }
                                }
                            }
                        }
                        
                        $model->save();
                    }
                }
            }
        }
        
        public function install_users_roles($bundle){
            if ($bundle instanceof \adapt\bundle){
                if (is_array($this->_roles[$bundle->name])){
                    foreach($this->_roles[$bundle->name] as $roles){
                        if(is_array($roles['role'])){
                            foreach ($roles as $role) {
                                $model_role = new model_role();
                                $model_user = new model_user();
                                if($model_role->load_by_name($role['role']) && $model_user->load_by_name($role['username'])){
                                    $model_role_user = new model_role_user();
                                    $model_role_user->role_id = $model_role->role_id;
                                    $model_role_user->user_id = $model_user->user_id;
                                    $model_role_user->save();
                                }
                            }
                        }
                        if(is_array($roles['permission'])){
                            foreach ($roles as $role) {
                                $model_role = new model_role();
                                $model_permission = new model_permission();
                                if($model_role->load_by_name($role['role']) && $model_permission->load_by_name($role['permission'])){
                                    $model_role_permission = new model_role_permission();
                                    $model_role_permission->role_id = $model_role->role_id;
                                    $model_role_permission->permission_id = $model_permission->permission_id;
                                    $model_role_permission->save();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

?>
