<?php

namespace adapt\users\roles_and_permissions{

    /* Prevent Direct Access */
    defined('ADAPT_STARTED') or die;
    
    class view_password_change extends \adapt\view{
        
        public function __construct($policy, $require_old_password = true, $user_data = array()){
            parent::__construct('div');
            $form_view = null;
            $form_title = null;
            $form = new \adapt\forms\model_form();
            
            $data = array();
            
            $data = array_merge($data, $this->request);
            
            $name = "change_password_with_policy";
            if ($require_old_password == false) $name = "new_password_with_policy";
            
            
            if ($form->load_by_name($name)){
                
                
                
                $form_view = $form->get_view($data);
                if ($form_view instanceof \adapt\html){
                    $form_title = $form_view->find('h1')->detach();
                    $form_title = $form_title->get(0);
                    $form_view->add_class('password-policy');
                }
            }
            
            $row = new \bootstrap\views\view_row();
            
            $left_col = new \bootstrap\views\view_cell(new html_h3('Change password'), 12, 12, 12, 12);
            //$right_col = new \bootstrap\views\view_cell(new html_h3('Join now'), 12, 12, 6, 6);
            $left_col->add($form_view);
            
            if ($policy && $policy instanceof \adapt\model && $policy->table_name == "password_policy"){
                $requirments = new html_ul();
                if ($policy->password_history){
                    if ($policy->password_history == 1){
                        $requirments->add(new html_li("not be the same as your previous password."));
                    }else{
                        $requirments->add(new html_li("not be the same as your previous {$policy->password_history} passwords."));
                    }
                }
                
                if ($policy->min_length){
                    $form_view->attr('data-password-policy-min-length', $policy->min_length);
                    $requirments->add(new html_li("be at least {$policy->min_length} characters long."));
                }
                
                if ($policy->max_length){
                    $form_view->attr('data-password-policy-max-length', $policy->max_length);
                    $requirments->add(new html_li("not be more than {$policy->max_length} characters long."));
                }
                
                if ($policy->mixed_case == "Yes"){
                    $requirments->add(new html_li("contain both upper and lower case characters."));
                    $form_view->attr('data-password-policy-mixed-case', "Yes");
                }elseif($policy->include_alpha == "Yes"){
                    $form_view->attr('data-password-policy-alpha', "Yes");
                    $requirments->add(new html_li("contain at least one letter from A-Z"));
                }
                
                if ($policy->include_numeric == "Yes"){
                    $form_view->attr('data-password-policy-numeric', "Yes");
                    $requirments->add(new html_li("contain at least one number, more is better."));
                }
                
                if ($policy->include_symbols == "Yes"){
                    $form_view->attr('data-password-policy-symbols', "Yes");
                    $requirments->add(new html_li("contain at least one symbol, more is better."));
                }
                
                if ($requirments->count()){
                    $wrapper = new html_div("Your new password must:");
                    $wrapper->add($requirments);
                    $this->set_variables(array('policy-description' => $wrapper));
                }
            }
            
            
            $row->add($left_col);
            
            
            $panel = new \bootstrap\views\view_panel($row);
            $this->add($panel);
            
            if ($form_title) $panel->title = $form_title;
            
            
            
            
            
        }
        
    }
    
}


?>