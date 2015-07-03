<?php
class loginxeclientController extends loginxeclient
{
	function init()
	{
	}

	function triggerDeleteLoginxeclientMember($args)
	{
		$cond = new stdClass();
		$cond->srl = $args->member_srl;
		$output = executeQuery('loginxeclient.deleteLoginxeclientMember', $cond);

		return;
	}

	function triggerLoginxeclientAddMemberMenu()
	{
		$logged_info = Context::get('logged_info');
		if(!Context::get('is_logged')) return new Object();
		//$target_srl = Context::get('target_srl');

		$oMemberController = getController('member');
		$oMemberController->addMemberMenu('dispLoginxeclientListProvider', Context::getLang('loginxecli_membermenu'));

		if($logged_info->is_admin== 'Y')
		{
			//$url = getUrl('','act','dispNcenterliteUserConfig','member_srl',$target_srl);
			//$oMemberController->addMemberPopupMenu($url, '유저 알림 설정', '');
		}

		return new Object();
	}

	function triggerDisablePWChk($args)
	{
		$cond = new stdClass();
		$cond->srl = $args->member_srl;
		$cond->type = 'mw';
		$output = executeQuery('loginxeclient.getLoginxeclientMemberbySrl', $cond);
		if(isset($output->data->enc_id)) $_SESSION['rechecked_password_step'] = 'INPUT_DATA';

		$cond->type = 'github';
		$output = executeQuery('loginxeclient.getLoginxeclientMemberbySrl', $cond);
		if(isset($output->data->enc_id)) $_SESSION['rechecked_password_step'] = 'INPUT_DATA';
		return;
	}

	function procLoginxeclientOAuthJoin()
	{
		$oMemberModel = getModel('member');
		$config = $oMemberModel->getMemberConfig();

		if($config->agreement && Context::get('accept_loginxe_agreement')!='Y') return $this->stop('msg_accept_agreement');

		$mt = microtime();
		$mt_rand = mt_rand();
		$password = md5($mt_rand);

		$_SESSION['loginxetemp_joindata']->password = $password;
		return $this->_doLoginXEJoin($_SESSION['loginxetemp_joindata']);
	}

	/*
	 * $func_arg
	 * child
	 *  - email
	 *  - nick_name
	 *  - state
	 *  - enc_id
	 *  - type
	 *  - profile
	 *  - password
	 */
	function _doLoginXEJoin($func_arg)
	{
		$oMemberModel = getModel('member');
		$config = $oMemberModel->getMemberConfig();
		$oMemberController = getController('member');
		$oLoginXEServerModel = getModel('loginxeclient');
		$module_config = $oLoginXEServerModel->getConfig();

		// call a trigger (before)
		$trigger_output = ModuleHandler::triggerCall ('member.procMemberInsert', 'before', $config);
		if(!$trigger_output->toBool ()) return $trigger_output;
		// Check if an administrator allows a membership or module config allows external join function
		if($module_config->loginxe_joinenable=='') $module_config->loginxe_joinenable='true';
		if($module_config->loginxe_joinenable != 'true')
		{
			return new Object(-1,'msg_signup_disabled');
		}

		if($func_arg->confirmed_email!="1") {
			$func_arg->email = $func_arg->type . substr(md5($func_arg->enc_id), 0, 6) . '@librewiki.net';
		}

		if($oMemberModel->getMemberInfoByEmailAddress($func_arg->email))
		{
			return new Object(-1,'loginxecli_duplicate_email');
		}

		$args = new stdClass();
		list($args->email_id, $args->email_host) = explode('@', $func_arg->email);
		$args->allow_mailing="N";
		$args->allow_message="Y";
		$args->email_address=$func_arg->email;
		$args->find_account_answer=md5($func_arg->state) . '@' . $args->email_host;
		$args->find_account_question="1";
		$args->nick_name=$func_arg->nick_name;
		$args->password=$func_arg->password;

		// check password strength
		if(!$oMemberModel->checkPasswordStrength($args->password, $config->password_strength))
		{
			$message = Context::getLang('about_password_strength');
			return new Object(-1, $message[$config->password_strength]);
		}

		$args->user_id = $func_arg->type . substr(md5($func_arg->enc_id), 0, 6);
		$useN=FALSE;
		//if id's first char is number, add n for first char.
		if(preg_match('/[0-9]/',substr($args->user_id,0,1)))
		{
			$useN=TRUE;
			$args->user_id = 'lxe' . substr($args->email_id,0,17);
		}
		while($oMemberModel->getMemberInfoByUserID($args->user_id)){
			if($useN) $args->user_id = 'lxe' . substr($args->email_id,0,7) . substr(md5($func_arg->state . rand(0,9999)),0,10);
			else $args->user_id=substr($args->email_id,0,10) . substr(md5($func_arg->state . rand(0,9999)),0,10);
		}
		$args->user_name=$func_arg->nick_name;

		// remove whitespace
		$checkInfos = array('user_id', 'nick_name', 'email_address');
		$replaceStr = array("\r\n", "\r", "\n", " ", "\t", "\xC2\xAD");
		foreach($checkInfos as $val)
		{
			if(isset($args->{$val}))
			{
				$args->{$val} = str_replace($replaceStr, '', $args->{$val});
			}
		}

		$output = $oMemberController->insertMember($args);
		if(!$output->toBool()) return $output;

		$site_module_info = Context::get('site_module_info');
		if($site_module_info->site_srl > 0)
		{
			$columnList = array('site_srl', 'group_srl');
			$default_group = $oMemberModel->getDefaultGroup($site_module_info->site_srl, $columnList);
			if($default_group->group_srl)
			{
				$oMemberModel->addMemberToGroup($args->member_srl, $default_group->group_srl, $site_module_info->site_srl);
			}

		}
		$groups = $oMemberModel->getGroups($site_module_info->site_srl);
                foreach($func_arg->groups as $val) {
                        foreach($groups as $gval) {
                                switch ($gval->title) {
                                case "개발자":
                                        if ($val == "Developer") 
                                                $g_srl = $gval->group_srl;
                                        break;
                                case "사무관":
                                        if ($val == "bureaucrat")
                                                $g_srl = $gval->group_srl;
                                        break;
                                case "검사관":
                                        if ($val == "checkuser")
                                                $g_srl = $gval->group_srl;
                                        break;
                                case "자동 인증된 사용자":
                                        if ($val == "autoconfirmed")
                                                $g_srl = $gval->group_srl;
                                        break;
                                case "관리자":
                                        if ($val == "sysop")
                                                $g_srl = $gval->group_srl;
                                        break;
                                }
                                if($g_srl) {
                                        getController('member')->addMemberToGroup($args->member_srl, $g_srl, $site_module_info->site_srl);
                                }
				
				$g_srl = null;
                        }
                }

		$LoginXEMember = new stdClass();
		$LoginXEMember->srl = $args->member_srl;
		$LoginXEMember->enc_id = $func_arg->enc_id;
		$LoginXEMember->type=$func_arg->type;

		$output = executeQuery('loginxeclient.insertLoginxeclientMember', $LoginXEMember);
		if(!$output->toBool())
		{
			return new Object(-1,$output->message);
		}

		$tmp_file = sprintf('./files/cache/tmp/%d', md5(rand(111111,999999).$args->email_id));
		if(!is_dir('./files/cache/tmp')) FileHandler::makeDir('./files/cache/tmp');

		$ping_header = array();
		$ping_header['Pragma'] = 'no-cache';
		$ping_header['Accept'] = '*/*';

		$request_config = array();
		$request_config['ssl_verify_peer'] = false;

		FileHandler::getRemoteFile($func_arg->profile, $tmp_file,null, 10, 'GET', null,$ping_header,array(),array(),$request_config);

		if(file_exists($tmp_file))
		{
			$oMemberController->insertProfileImage($args->member_srl, $tmp_file);
		}

		if($config->identifier == 'email_address')
		{
			$oMemberController->doLogin($args->email_address, $args->password, true);
		}
		else
		{
			$oMemberController->doLogin($args->user_id, $args->password, true);
		}

		$_SESSION['rechecked_password_step'] = 'INPUT_DATA';

		if($config->redirect_url) $this->redirect_Url = $config->redirect_url;
		else $this->redirect_Url = getNotEncodedUrl('', 'act', 'dispMemberModifyInfo');

		FileHandler::removeFile($tmp_file);
		unset($_SESSION['loginxetemp_joindata']);

		return new Object();
	}
}
