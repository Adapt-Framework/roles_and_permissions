<?php

namespace adapt\users\roles_and_permissions{
    
    /* Prevent Direct Access */
    defined('ADAPT_STARTED') or die;
    
    class model_permission extends \adapt\model{
        
        const EVENT_ON_LOAD_BY_PHP_KEY = "model_permission.on_load_by_php_key";
        
        public function __construct($id = null, $data_source = null){
            parent::__construct("permission", $id, $data_source);
        }
        
        public function load_by_php_key($key){
            $this->initialise();
            
            if ($key){
                $sql = $this->data_source->sql;
                
                $sql->select('*')
                    ->from('permission')
                    ->where(
                        new sql_and(
                            new sql_cond('php_key', sql::EQUALS, sql::q($key)),
                            new sql_cond('date_deleted', sql::IS, new sql_null())
                        )
                    );
                
                $results = $sql->execute()->results();
                
                if (is_array($results)){
                    if (count($results) == 0){
                        $this->error("No permissions found with the PHP key '{$key}'");
                    }elseif(count($results) > 1){
                        $this->error("Multiple permissions found with the PHP key '{$key}'");
                    }elseif (count($results) == 1){
                        $this->trigger(self::EVENT_ON_LOAD_BY_PHP_KEY);
                        return $this->load_by_data($results);
                    }
                }
            }
            
            return false;
        }
        
    }
    
}

?>