<?php

namespace adapt\users\roles_and_permissions;

class model_password_policy extends \adapt\model
{
    public function __construct($id = null, $data_source = null)
    {
        parent::__construct('password_policy', $id, $data_source);
    }

    /**
     * Gets the password policy in an HTML format for injection
     * @return string
     */
    public function to_html()
    {
        if ($this->is_loaded) {
            $requirements = new html_ul();
            if ($this->password_history){
                if ($this->password_history == 1){
                    $requirements->add(new html_li("Not be the same as your previous password."));
                }else{
                    $requirements->add(new html_li("Not be the same as your previous {$this->password_history} passwords."));
                }
            }

            if ($this->min_length){
                $requirements->add(new html_li("Be at least {$this->min_length} characters long."));
            }

            if ($this->max_length){
                $requirements->add(new html_li("Not be more than {$this->max_length} characters long."));
            }

            if ($this->mixed_case == "Yes"){
                $requirements->add(new html_li("Contain both upper and lower case characters."));
            }elseif($this->include_alpha == "Yes"){
                $requirements->add(new html_li("Contain at least one letter from A-Z"));
            }

            if ($this->include_numeric == "Yes"){
                $requirements->add(new html_li("Contain at least one number, more is better."));
            }

            if ($this->include_symbols == "Yes"){
                $requirements->add(new html_li("Contain at least one symbol, more is better."));
            }

            if ($requirements->count()){
                $wrapper = new html_div("Your new password must:");
                $wrapper->add($requirements);
                return $wrapper->render();
            }
        }

        return '';
    }
}