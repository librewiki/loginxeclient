<?php
class loginxeclientView extends loginxeclient
{
	function init()
	{
		$this->setTemplatePath($this->module_path . 'tpl');
		$this->setTemplateFile(strtolower(str_replace('dispLoginxeclient', '', $this->act)));
	}

	function sign_request( $method, $url, $params = array() ) {
                global $gConsumerSecret, $gTokenSecret;

                $parts = parse_url( $url );

                // We need to normalize the endpoint URL
                $scheme = isset( $parts['scheme'] ) ? $parts['scheme'] : 'http';
                $host = isset( $parts['host'] ) ? $parts['host'] : '';
                $port = isset( $parts['port'] ) ? $parts['port'] : ( $scheme == 'https' ? '443' : '80' );
                $path = isset( $parts['path'] ) ? $parts['path'] : '';
                if ( ( $scheme == 'https' && $port != '443' ) ||
                        ( $scheme == 'http' && $port != '80' )
                ) {
                        // Only include the port if it's not the default
                        $host = "$host:$port";
                }

                // Also the parameters
                $pairs = array();
                parse_str( isset( $parts['query'] ) ? $parts['query'] : '', $query );
                $query += $params;
                unset( $query['oauth_signature'] );
                if ( $query ) {
                        $query = array_combine(
                                // rawurlencode follows RFC 3986 since PHP 5.3
                                array_map( 'rawurlencode', array_keys( $query ) ),
                                array_map( 'rawurlencode', array_values( $query ) )
                        );
                        ksort( $query, SORT_STRING );
                        foreach ( $query as $k => $v ) {
                                $pairs[] = "$k=$v";
                        }
                }

                $toSign = rawurlencode( strtoupper( $method ) ) . '&' .
                        rawurlencode( "$scheme://$host$path" ) . '&' .
                        rawurlencode( join( '&', $pairs ) );
                $key = rawurlencode( $gConsumerSecret ) . '&' . rawurlencode( $gTokenSecret );
                return base64_encode( hash_hmac( 'sha1', $toSign, $key, true ) );
        }


	function dispLoginxeclientListProvider()
	{
		$oLoginXEServerModel = getModel('loginxeclient');
		$module_config = $oLoginXEServerModel->getConfig();

		Context::set('module_config', $module_config);

		$oMemberModel = getModel('member');
		$oMemberConfig = $oMemberModel->getMemberConfig();
		$skin = $oMemberConfig->skin;

		if(!$skin)
		{
			$skin = 'default';
			$template_path = sprintf('./modules/member/skins/%s', $skin);
		}
		else
		{
			//check theme
			$config_parse = explode('|@|', $skin);
			if (count($config_parse) > 1)
			{
				$template_path = sprintf('./themes/%s/modules/member/', $config_parse[0]);
			}
			else
			{
				$template_path = sprintf('./modules/member/skins/%s', $skin);
			}
		}

		Context::set('memberskin',$template_path);

		//TODO 다국어화
		$logindata = new stdClass();
		$logindata->mw = new stdClass();
		$logindata->mw->id = 'mw';
		$logindata->mw->title = Context::getLang('loginxe_mw_provider');
		$logindata->mw->connected = false;
		$logindata->github = new stdClass();
		$logindata->github->id = 'github';
		$logindata->github->title = Context::getLang('loginxe_github_provider');
		$logindata->github->connected = false;

		$cond = new stdClass();
		$cond->srl=Context::get('logged_info')->member_srl;
		$cond->type='mw';
		$output = executeQuery('loginxeclient.getLoginxeclientMemberbySrl', $cond);

		if(isset($output->data->enc_id))
		{
			$logindata->mw->connected = true;
		}

		$cond = new stdClass();
		$cond->srl=Context::get('logged_info')->member_srl;
		$cond->type='github';
		$output = executeQuery('loginxeclient.getLoginxeclientMemberbySrl', $cond);

		if(isset($output->data->enc_id))
		{
			$logindata->github->connected = true;
		}

		Context::set('providers',$logindata);
	}

	function dispLoginxeclientOAuthFinish()
	{
		global $gConsumerSecret, $gTokenSecret;
		$oLoginXEServerModel = getModel('loginxeserver');
                $module_config = $oLoginXEServerModel->getConfig();
		$gConsumerKey = $module_config->clientid;
		$gConsumerSecret = $module_config->clientkey;
		$gTokenSecret = $_SESSION['loginxe_secret'];
		$oMemberModel = getModel('member');
		$config = $oMemberModel->getMemberConfig();
		//Context::set('member_config',$config);
		Context::set('layout',null);

		$oMemberController = getController('member');
		$oLoginXEServerModel = getModel('loginxeclient');
		$module_config = $oLoginXEServerModel->getConfig();

		//use_sessiondata가 true면 로그인 서버에 다시 요청하지 않음(key 만료로 인한 오류 방지)
		if(Context::get('use_sessiondata')=='true') return;
		if(Context::get('token')=='') return new Object(-1,'No token given.');

		$token = rawurldecode(Context::get('token'));
		if($token=='') return new Object(-1,'No token given.');
		$state = Context::get('state');
		$service = Context::get('provider');

		//SSL 미지원시 리턴
		if(!$this->checkOpenSSLSupport())
		{
			return new Object(-1,'loginxecli_need_openssl');
		}

		//state가 다르면 리턴(CSRF 방지)
		if($state!=$_SESSION['loginxecli_state'])
		{
			return new Object(-1,'msg_invalid_request');
		}

		//활성화된 서비스가 아닐경우 오류 출력
		if(!in_array($service, $module_config->loginxe_provider))
		{
			return new Object(-1,sprintf(Context::getLang('loginxecli_not_enabled_provider'), Context::getLang('loginxe_' . $service . '_provider')));
		}

		if($service=='mw')
		{
			//받아온 인증키로 바로 회원 정보를 얻어옴
			$ping_url = 'https://librewiki.net/wiki/%ED%8A%B9%EC%88%98:MWO%EC%9D%B8%EC%A6%9D/identify';

			$ping_header = array();
			$ping_header['oauth_consumer_key'] = $gConsumerKey;
			$ping_header['oauth_token'] = $token;
			$ping_header['oauth_version'] = '1.0';
			$ping_header['oauth_nonce'] = md5( microtime() . mt_rand() );
			$ping_header['oauth_timestamp'] = time();
			$ping_header['oauth_signature_method'] = 'HMAC-SHA1';

			$signature = $this->sign_request( 'GET', $ping_url, $ping_header );
			$ping_header['oauth_signature'] = $signature;
		
			$header = array();
			foreach ( $ping_header as $k => $v ) {
				$header[] = rawurlencode( $k ) . '="' . rawurlencode( $v ) . '"';
			}
			$header['Authorization'] = 'OAuth ' . join( ', ', $header );
	
			$request_config = array();
			$request_config['ssl_verify_peer'] = false;

			$buff = FileHandler::getRemoteResource($ping_url, null, 10, 'GET', 'application/x-www-form-urlencoded', $header, array(), array(), $request_config);

			$fields = explode( '.', $buff );
			if ( count( $fields ) !== 3 ) {
				return new Object(-1,'제대로 값을 받지 못하였습니다.');
			}

			$header = base64_decode( strtr( $fields[0], '-_', '+/' ), true );
		        if ( $header !== false ) {
		                $header = json_decode( $header );
		        }
		        if ( !is_object( $header ) || $header->typ !== 'JWT' || $header->alg !== 'HS256' ) {
				return new Object(-1,'해더값이 올바르지 않습니다.');
		        }

			$sig = base64_decode( strtr( $fields[2], '-_', '+/' ), true );
			$check = hash_hmac( 'sha256', $fields[0] . '.' . $fields[1], $gConsumerSecret, true );
			if ( $sig !== $check ) {
				return new Object(-1,'인증해시가 맞지 않습니다.');
			}

			$payload = base64_decode( strtr( $fields[1], '-_', '+/' ), true );
			if ( $payload !== false ) {
		                $payload = json_decode( $payload );
		        }
		        if ( !is_object( $payload ) ) {
				return new Object(-1,'디코딩을 실패하였습니다.');
		        }

			//로그인이 안되어 있다면 enc_id로 가입 여부 체크
			$cond = new stdClass();
			$cond->enc_id=$payload->username;
			$cond->type=$service;
			$output = executeQuery('loginxeclient.getLoginxeclientbyEncID', $cond);

			//srl이 있다면(로그인 시도)
			if(isset($output->data->srl))
			{
				$member_Info = $oMemberModel->getMemberInfoByMemberSrl($output->data->srl);
				if($config->identifier == 'email_address')
				{
					$oMemberController->doLogin($member_Info->email_address,'',true);
				}
				else
				{
					$oMemberController->doLogin($member_Info->user_id,'',true);
				}
					//회원정보 변경시 비밀번호 입력 없이 변경 가능하도록 수정
				$_SESSION['rechecked_password_step'] = 'INPUT_DATA';
				if($config->after_login_url) $this->redirect_Url = $config->after_login_url;
				$this->redirect_Url = getUrl('');
			}
			else
			{
				/*
				 * $func_arg
				 * child
				 *  - email $xmlDoc->data->response->email->body;
				 *  - nick_name $xmlDoc->data->response->nickname->body;
				 *  - state $state
				 *  - enc_id $xmlDoc->data->response->enc_id->body;
				 *  - type $service
				 *  - profile $xmlDoc->data->response->profile_image->body
				 */
				$funcarg = new stdClass();
				$funcarg->email = $payload->email;
				$funcarg->nick_name = $payload->username;
				$funcarg->state = $state;
				$funcarg->enc_id = $payload->username;
				$funcarg->type = $service;
				$funcarg->profile = null;
				$funcarg->confirmed_email = $payload->confirmed_email;
				$funcarg->groups = $payload->groups;
				$_SESSION['loginxetemp_joindata'] = $funcarg;
				getController('loginxeclient')->procLoginxeclientOAuthJoin();
			}
		}
		Context::set('url',$this->redirect_Url);
	}

	function dispLoginxeclientOAuth()
	{
		//oauth display & redirect act
		//load config here and redirect to service
		//key check & domain check needed
		//needed value=service,id,key,state(client-generated),callback-url(urlencoded)
		$service = Context::get('provider');
		$oLoginXEServerModel = getModel('loginxeclient');
		$module_config = $oLoginXEServerModel->getConfig();
		//설정에서 체크하지 않은 provider일 경우 잘못된 요청입니다 출력
		if(!in_array($service, $module_config->loginxe_provider))
		{
			return new Object(-1,'msg_invalid_request');
		}
		//state 생성
		$_SESSION['loginxecli_state'] = $this->generate_state();

		//서버 주소로 이동
		Context::set('url',$module_config->loginxe_server . sprintf("/index.php?module=loginxeserver&act=dispLoginxeserverOAuth&provider=%s&id=%s&key=%s&state=%s&callback=%s",$service,$module_config->loginxe_id,$module_config->loginxe_key,$_SESSION['loginxecli_state'],urlencode(getNotEncodedFullUrl('','module','loginxeclient','act','dispLoginxeclientOAuthFinish','provider',$service))));
	}
	function generate_state() {
		$mt = microtime();
		$rand = mt_rand();
		return md5($mt . $rand);
	}
}
