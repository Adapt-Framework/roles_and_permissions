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

    public function __construct($id = null, $data_source = null)
    {
        parent::__construct('role', $id, $data_source);
    }
    
    public function permission_delete(){
        if ($this->is_loaded && $this->session->user->permission_level < $this->highest_level){
            return false;
        }
        
        return true;
    }

    /**
     * Loads the permissions into the role
     * @param array $data
     * @return bool
     */
    public function load_by_data($data = array())
    {
        if (parent::load_by_data($data)) {
            $this->_permissions = [];

            if ($this->is_loaded && $this->role_id) {
                // Load the permissions
                $sql = $this->data_source->sql;
                $sql->select('p.permission_id as permission_id')
                    ->from('permission', 'p')
                    ->join('role_permission', 'rp', 'permission_id')
                    ->where(new sql_and(
                        new sql_cond('p.date_deleted', sql::IS, sql::NULL),
                        new sql_cond('rp.date_deleted', sql::IS, sql::NULL),
                        new sql_cond('rp.role_id', sql::EQUALS, $this->role_id)
                    ));

                $results = $sql->execute()->results();

                // Normalise the array
                $ids = array();
                foreach ($results as $result) {
                    $ids[] = $result['permission_id'];
                }

                if (count($results) > 0) {
                    $this->_permissions = model_permission::load_many('permission', $ids);
                }
            }

            return true;
        }

        return false;
    }

    /**
     * Returns the permissions as models
     * @return array
     */
    public function pget_perms()
    {
        return $this->_permissions;
    }

    /**
     * Returns the permissions in array format
     * @return array
     */
    public function mget_permissions()
    {
        $output = array();

        foreach ($this->_permissions as $permission) {
            if ($permission instanceof \adapt\model && $permission->is_loaded) {
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