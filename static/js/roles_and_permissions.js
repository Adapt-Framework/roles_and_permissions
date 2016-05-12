(function($){
    
    $(document).ready(function(){
        
        $(".view.form.password-policy input[type='password'][name='new_password']").on(
            'blur',
            function(event){
                var valid = true;
                var $this = $(this);
                var value = $this.val();
                var $form = $this.parents('form.password-policy');
                
                if ($form.attr('data-password-policy-min-length')) {
                    if (value.length < parseInt($form.attr('data-password-policy-min-length'))) {
                        valid = false;
                    }
                }
                
                if ($form.attr('data-password-policy-max-length')) {
                    if (value.length > parseInt($form.attr('data-password-policy-max-length'))) {
                        valid = false;
                    }
                }
                
                if ($form.attr('data-password-policy-mixed-case') == "Yes") {
                    if (!/[A-Z]+[a-z]+|[a-z]+[A-Z]+/.exec(value)){
                        valid = false;
                    }
                }
                
                if ($form.attr('data-password-policy-alpha') == "Yes") {
                    if (!/[a-zA-Z]/.exec(value)){
                        valid = false;
                    }
                }
                
                if ($form.attr('data-password-policy-numeric') == "Yes") {
                    if (!/[0-9]/.exec(value)){
                        valid = false;
                    }
                }
                
                if ($form.attr('data-password-policy-symbols') == "Yes") {
                    if (!/[$-/:-?{-~!"^_`\[\]@]/.exec(value)){
                        valid = false;
                    }
                }
                
                $this.parent().find('.glyphicon').detach();
                
                if (valid){
                    $this.parents('.form-group').addClass('has-success').removeClass('has-error').addClass('has-feedback').find('input').after('<span class="glyphicon glyphicon-ok form-control-feedback" aria-hidden="true"></span>');
                }else{
                    $this.parents('.form-group').addClass('has-error').removeClass('has-success').addClass('has-feedback').find('input').after('<span class="glyphicon glyphicon-remove form-control-feedback" aria-hidden="true"></span>');
                    $this.parents('.forms.view.form').find('#' + $this.parents('.form-control').attr('data-form-page-id')).removeClass('selected').addClass('error');
                }
            }
        )
        
    });
    
})(jQuery);