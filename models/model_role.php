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
            if ($output instanceof \adapt\model && $output->is_loaded) {
                $output[] = $permission->to_hash();
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
}