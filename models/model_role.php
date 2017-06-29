<?php

namespace adapt\users\roles_and_permissions;

defined('ADAPT_STARTED') or die;

class model_role extends \adapt\model
{
    /**
     * The permissions this role has
     * @var array
     */

    protected $_permissions;
    protected $_disable_permission_checks;

    public function __construct($id = null, $data_source = null){
        parent::__construct('role', $id, $data_source);
        $this->_disable_permission_checks = false;
    }
    
    public function pget_disable_permission_checks(){
        return $this->_disable_permission_checks;
    }
    
    public function pset_disable_permission_checks($check){
        $this->_disable_permission_checks = $check;
    }
    
    public function permission_delete(){
        return $this->permission_edit();
    }
    
    public function permission_edit(){
        if ($this->_disable_permission_checks || $this->is_loaded && $this->session->user->permission_level < $this->highest_level){
            return false;
        }
        
        return true;
    }

    /**
     * Loads the permissions into the role
     * @param array $data
     * @return bool
     */
    public function load_by_data($data = array()){
        if (parent::load_by_data($data)) {
            if ($this->is_loaded && $this->role_id) {
                
                // Load the permissions
                $sql = $this->data_source->sql;
                $sql->select('p.permission_id as permission_id, role_permission_id')
                    ->from('permission', 'p')
                    ->join('role_permission', 'rp', 'permission_id')
                    ->where(new sql_and(
                        new sql_cond('p.date_deleted', sql::IS, sql::NULL),
                        new sql_cond('rp.date_deleted', sql::IS, sql::NULL),
                        new sql_cond('rp.role_id', sql::EQUALS, $this->role_id)
                    ));

                $results = $sql->execute()->results();

                // Normalise the array
                $permission_ids = array();
                $role_permission_ids = array();
                foreach ($results as $result) {
                    $permission_ids[] = $result['permission_id'];
                    if (!in_array($result['role_permission_id'], $role_permission_ids)){
                        $role_permission_ids[] = $result['role_permission_id'];
                    }
                }

                if (count($results) > 0) {
                    $permissions = model_permission::load_many('permission', $permission_ids);
                    foreach($permissions as $permission){
                        $this->_permissions[] = $permission;
                    }
                    
                    $role_permissions = model_role_permission::load_many('role_permission', $role_permission_ids);
                    foreach($role_permissions as $role_permission){
                        $this->add($role_permission);
                    }
                }
                
                /* Load the users */
                $sql = $this->data_source->sql;
                $sql->select('*')
                    ->from('role_user')
                    ->where(
                        new sql_and(
                            new sql_cond('role_id', sql::EQUALS, $this->role_id),
                            new sql_cond('date_deleted', sql::IS, sql::NULL)
                        )
                    );
                
                $results = $sql->execute()->results();
                foreach($results as $result){
                    $model = new model_role_user();
                    if ($model->load_by_data($result)){
                        $this->add($model);
                    }
                }
            }

            return true;
        }

        return false;
    }

    
    /**
     * @TODO: Check permission levels
     */
    public function add_user_by_username($username){
        $user = new model_user();
        if ($user->load_by_username($username)){
            return $this->add_user_by_user_id($user->user_id);
        }
        
        return false;
    }
    
    public function add_user_by_user_id($user_id){
        if (!$this->permission_edit() && !$this->_disable_permission_checks){
            $this->error('You are not permitted to do this.');
            return false;
        }
        
        if (!$this->has_user($user_id)){
            $model = new model_role_user();
            $model->user_id = $user_id;
            $this->add($model);
            return true;
        }
        
        return false;
    }
    
    public function add_user_by_email_address($email_address){
        $user = new model_user();
        if ($user->load_by_email_address($email_address)){
            return $this->add_user_by_user_id($user->user_id);
        }
        
        return false;
    }
    
    public function has_user($user_id){
        if (!$this->permission_edit() && !$this->_disable_permission_checks){
            $this->error('You are not permitted to do this.');
            return false;
        }
        
        $children = $this->get();
        foreach($children as $child){
            if ($child instanceof \adapt\model && $child->table_name == 'role_user'){
                if ($child->user_id == $user_id){
                    return true;
                }
            }
        }
        
        return false;
    }
    
    public function add_permission_by_permission_id($permission_id){
        if (!$this->permission_edit() && !$this->_disable_permission_checks){
            $this->error('You are not permitted to do this.');
            return false;
        }
        
        $permission = new model_permission($permission_id);
        if (!$permission->is_loaded){
            $this->error("Unknown permission {$permission_id}");
            return false;
        }
        
        if ($permission->permission_level > $this->session->user->permission_level && !$this->_disable_permission_checks){
            $this->error('You are not permitted to do this.');
            return false;
        }
        
        if (!$this->has_permission($permission_id)){
            $model = new model_role_permission();
            $model->permission_id = $permission_id;
            $this->add($model);
            return true;
        }
        
        return false;
    }
    
    public function add_permission_by_name($permission_name){
        $permission = new model_permission();
        if ($permission->load_by_name($permission_name)){
            return $this->add_permission_by_permission_id($permission->permission_id);
        }
        
        return false;
    }
    
    public function has_permission($permission_id){
        if (!$this->permission_edit() && !$this->_disable_permission_checks){
            $this->error('You are not permitted to do this.');
            return false;
        }
        
        $children = $this->get();
        foreach($children as $child){
            if ($child instanceof \adapt\model && $child->table_name == "role_permission"){
                if ($child->permission_id == $permission_id){
                    return true;
                }
            }
        }
        
        return false;
    }
    
    public function remove_user_by_user_id($user_id){
        if (!$this->permission_edit() && !$this->_disable_permission_checks){
            $this->error('You are not permitted to do this.');
            return false;
        }
        
        if ($this->has_user($user_id)){
            $children = $this->get();
            foreach($children as $child){
                if ($child instanceof \adapt\model && $child->table_name == "role_user"){
                    if ($child->user_id == $user_id){
                        $child->delete();
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    public function remove_user_by_username($username){
        $user = new model_user();
        if ($user->load_by_username($username)){
            return $this->remove_user_by_user_id($user->user_id);
        }
        
        return false;
    }
    
    public function remove_user_by_email_address($email_address){
        $user = new model_user();
        if ($user->load_by_email_address($email_address)){
            return $this->remote_user_by_user_id($user->user_id);
        }
        
        return false;
    }
    
    public function remove_permission_by_permission_id($permission_id){
        if (!$this->permission_edit() || !$this->_disable_permission_checks){
            $this->error('You are not permitted to do this.');
            return false;
        }
        
        $permission = new model_permission($permission_id);
        if (!$permission->is_loaded){
            $this->error("Unknown permission {$permission_id}");
            return false;
        }
        
        if ($permission->permission_level > $this->session->user->permission_level){
            $this->error('You are not permitted to do this.');
            return false;
        }
        
        if ($this->has_permission($permission_id)){
            $children = $this->get();
            foreach($children as $child){
                if ($child instanceof \adapt\model && $child->table_name == 'role_permission'){
                    if ($child->permission_id == $permission_id){
                        $child->delete();
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    public function remove_permission_by_name($permission_name){
        $permission = new model_permission();
        if ($permission->load_by_name($permission_name)){
            return $this->remove_permission_by_permission_id($permission->permission_id);
        }
        
        return false;
    }
    /**
     * Returns the permissions as models
     * @return array
     */
    public function pget_perms(){
        return $this->_permissions;
    }

    /**
     * Returns the permissions in array format
     * @return array
     */
    public function mget_permissions(){
        foreach ($this->_permissions as $permission) {
            if ($permission instanceof \adapt\model && $permission->table_name = "role_permission" && $permission->is_loaded) {
                $output[] = $permission->to_hash()['permission'];
            }
        }

        return $output;
    }

    /**
     * Gets the highest permission level associated with this role
     * @return int
     */
    public function mget_highest_level()
    {
        $level = 0;
        foreach ($this->_permissions as $permission) {
            if ($permission->permission_level > $level) {
                $level = $permission->permission_level;
            }
        }

        return $level;
    }

    /**
     * Deletes a role
     * @return bool
     */
    public function delete(){
        // Tidy up the role_permissions table
        $this->delete_permissions();
        $this->delete_users();

        // Return the actual delete
        return parent::delete();
    }

    /**
     * Function that clears all the current permission links for a role
     */
    public function delete_permissions(){
        if ($this->is_loaded && $this->role_id && $this->permission_delete()) {
            $sql = $this->data_source->sql;
            $sql->update('role_permission')
                ->set('date_deleted', new sql_now())
                ->where(new sql_and(
                    new sql_cond('date_deleted', sql::IS, sql::NULL),
                    new sql_cond('role_id', sql::EQUALS, $this->role_id)
                ));

            $sql->execute();
        }
    }
    
    /**
     * Method to remove all users from the group
     */
    public function delete_users(){
        if ($this->is_loaded && $this->role_id && $this->permission_delete()) {
            $sql = $this->data_source->sql;
            $sql->update('role_user')
                ->set('date_deleted', new sql_now())
                ->where(new sql_and(
                    new sql_cond('date_deleted', sql::IS, sql::NULL),
                    new sql_cond('role_id', sql::EQUALS, $this->role_id)
                ));

            $sql->execute();
        }
    }
}