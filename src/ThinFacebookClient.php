<?php
/**
 * Thin Facebook Client: A thin PHP client for the Facebook Graph API and oAuth.
 *
 * Copyright (c) 20010-2011 Michael Henretty
 *
 * Distributed under the terms of the MIT License.
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright  2010-2011 Michael Henretty <michael.henretty@gmail.com>
 * @license    http://www.opensource.org/licenses/mit-license.php The MIT License
 * @link       http://github.com/mikehenrty/thin-pdo-wrapper
 */


/**
 * A thin PHP client for the Facebook Graph API and oAuth
 * @author Michael Henretty
 */
class ThinFacebookClient {
	
	const USE_SESSION = true;
	const SESSION_KEY = 'generate_your_own_random_string';
	
	protected $app_id;
	protected $app_secret;
	protected $app_url;
	protected $canvas_url;
	protected $canvas_domain;
	
	protected $user_id;
	protected $auth_token;
	protected $expires_on;
	
	/**
	 * Boot up our client, store app id and secret with the instance
	 * 	- start the session
	 * 
	 * @param int $app_id - the Facebook application ID
	 * @param string $app_secret - the Facebook application secret
	 * @param string $app_url - the url to the app on facebook
	 * @param string $canvas_url - the url of this application
	 * @param string $canvas_domain - the cookie domain for the session
	 * @param string $auth_token (optional) - the authenticatoin token
	 */
	public function __construct($app_id, $app_secret, $app_url, $canvas_url, $canvas_domain, $auth_token=null) {
		// populate our basic info
		$this->app_id = $app_id;
		$this->app_secret = $app_secret;
		$this->app_url = $app_url;
		$this->canvas_url = $canvas_url;
		$this->canvas_domain = $canvas_domain;
		
		// use the auth token if we were passed on
		if (!empty($auth_token)) {
			$this->auth_token = $auth_token;
		}
		
		// if we are using sessions, attempt to restore latest session
		// and register a save session function on request shutdown
		else {
			if (self::USE_SESSION) {
				$this->restoreSession();
			}
			
			// now we initialize our authorization status
			$this->initAuth();
		}
	}
	
	/**
	 * Check if the user has been authorized (look for access_token)
	 */
	public function isAuthorized() {
		return !empty($this->auth_token);
	}
	
	/**
	 * Saves as a session the information stored in this FB object
	 */
	protected function saveSession() {
		// make sure we have an auth token before saving
		if (empty($this->auth_token)) {
			return;
		}
		
		$session_info = array(
			'user_id' => $this->user_id,
			'auth_token' => $this->auth_token,
			'expires_on' => $this->expires_on
		);
		$session_str = json_encode(array_filter($session_info));
		
		setcookie(self::SESSION_KEY, $session_str, $this->expires_on, '/', $this->canvas_domain, false, false);
	}
	
	/**
	 * Check for existing session, and restore our data if so
	 */
	protected function restoreSession() {
		if (isset($_COOKIE[self::SESSION_KEY])) {
			$session_info = json_decode($_COOKIE[self::SESSION_KEY], true);
			
			$this->user_id = isset($session_info['user_id']) ? $session_info['user_id'] : null;
			$this->auth_token = isset($session_info['auth_token']) ? $session_info['auth_token'] : null;
			$this->expires_on = isset($session_info['expires_on']) ? $session_info['expires_on'] : null;
		}
	}
	
	/**
	 * Clears the current session
	 */
	protected function clearSession() {
		setcookie($_COOKIE[self::SESSION_KEY], '', time()-3600, '/', $this->canvas_domain, false, false);
	}
	
	/**
	 * Check if the current request has a valid access token, store it locally if so
	 */
	public function initAuth() {
		if (isset($_REQUEST['signed_request'])) {
			// decode the request into a signature and data
			list($encoded_sig, $payload) = explode('.', $_REQUEST['signed_request'], 2);
			$sig = base64_decode(strtr($encoded_sig, '-_', '+/'));
			$data = json_decode(base64_decode(strtr($payload, '-_', '+/')), true);
			
			// if algorithm is not what we were expecting, ignore signed request
			if (strtoupper($data['algorithm']) !== 'HMAC-SHA256') {
				return;
			}
			
			// verify the signture
			$expected_sig = hash_hmac('sha256', $payload, $this->app_secret, true);
			if ($sig !== $expected_sig) {
				return;
			}
			
			// now store the data from the signed request on this object
			$this->auth_token = isset($data['oauth_token']) ? $data['oauth_token'] : null;
			$this->user_id = isset($data['user_id']) ? $data['user_id'] : null;
			$this->expires_on = isset($data['expires']) ? $data['expires'] : null;
			
			// save the new session
			if (self::USE_SESSION) {
				$this->saveSession();
			}
		}
		
		// if no token available, check if we are attempting to authorize
		// and if so, use the request object 'code' to request access token
		else if (!empty($_REQUEST['code'])) {
			$now = time();
			
			$response = $this->curlPost(
				'https://graph.facebook.com/oauth/access_token', 
				array(
					'client_id' => $this->app_id,
					'client_secret' => $this->app_secret,
					'redirect_uri' => $this->canvas_url,
					'code' => $_REQUEST['code']
				)
			);
			
			// store information on this object
			parse_str($response, $response_array);
			$this->auth_token = isset($response_array['access_token']) ? $response_array['access_token'] : $this->auth_token;
			$this->expires_on = isset($session_info['expires']) ? (intval($response_array['expires'])+$now) : $this->expires_on;
			
			// save the new session
			if (self::USE_SESSION) {
				$this->saveSession();
			}
		}
	}
	
	/**
	 * Redirect to the FB oAuth page to authenticate user
	 * 
	 * @param array $extra - any extra data we want passed back after auth
	 */
	public function redirectAuthorize($extra) {
		$redirect_uri = $this->app_url;
		if (!empty($extra)) {
			$redirect_uri .= ( strpos($this->app_url, '?')===false ? '?' : '&') . '__p='.urlencode(json_encode($extra));
		}
		
		$this->redirect(
			'https://www.facebook.com/dialog/oauth', 
			array(
				'client_id' => $this->app_id,
				'redirect_uri' => $redirect_uri
			)
		);
	}
	
	/**
	 * Get's any data passed back from auth request
	 */
	public function getAuthPassback() {
		return (!empty($_GET['__p']) ? json_decode($_GET['__p'], true) : false);
	}
	
	public function getFbUserid() {
		// first see if we have the userid store on the object
		if (!empty($this->user_id)) {
			return $this->user_id;
		}
		
		// if we have an access token, attempt to get userinfo from the graph
		else if (!empty($this->auth_token)) {
			$user_info = $this->getUserInfo();
			return (!empty($user_info) && !empty($user_info['id'])) ? $user_info['id'] : false;
		}
		
		// if we have neither a user or access token, the session has expired
		else {
			return false;
		}
	}
	
	/**
	 * Get the user information of a FB user
	 * @param int $fbuid
	 */
	public function getUserInfo($fbuid) {
		// see if we have a cached version first
		static $user_info;
		if (!empty($user_info)) {
			return $user_info;
		}
		
		// build the fql query and url
		$fql_fields = array(
			'uid',
			'name',
			'first_name',
			'last_name',
			'about_me',
			'timezone',
			'email',
			'locale',
			'current_location',
			'affiliations',
			'profile_url',
			'sex',
			'pic_square',
			'pic_square_with_logo',
			'pic',
			'pic_with_logo',
			'pic_big',
			'pic_big_with_logo',
			'birthday',
			'birthday_date',
			'profile_blurb',
			'website',
			'activities',
			'interests',
			'music',
			'movies',
			'books',
			'website',
			'quotes',
			'work_history'
		);
		$fql_query = 'SELECT ' . implode(',', $fql_fields) . ' FROM user WHERE uid='.$fbuid;
		$fql_url = 'https://api.facebook.com/method/fql.query?access_token='.$this->auth_token.'&format=json&query='.urlencode($fql_query);
		
		// now make the actual request
		$response = $this->curlGet($fql_url);
		if (empty($response)) {
			return false;
		}
		
		// decode our response
		$response = json_decode($response, true);
		
		// check response for an error, and if error clear session and return false
		if (!empty($response['error'])) {
			if (self::USE_SESSION) {
				$this->clearSession();
			}
			return false;
		}
		
		return $response[0];
	}
	
	/**
	 * Gets the current users friends fb userids
	 */
	public function getFriends() {
		$response = $this->getGraphReponse('friends');
		return (isset($response['data']) ? $response['data'] : false);
	}
	
	/**
	 * Get a response from the graph
	 * 
	 * @param string $method - the graph api method to invoke
	 * @param array $params (optional) - the parameters to pass along with the call
	 * @param string $object (optional) - the object we are referencing, defaults to current user
	 * @return array - the response from the graph api
	 */
	public function getGraphReponse($method, $params=null, $object=null) {
		if (empty($object)) {
			$object = !empty($this->user_id) ? $this->user_id : 'me';
		}
		$graph_url = 'https://graph.facebook.com/'.$object.'/'.$method.'?access_token='.$this->auth_token;
		if (!empty($params)) {
			$graph_url .= '&'.http_build_query($params);
		}
		//return json_decode(file_get_contents($graph_url), true);
		
		// grab info from the server
		$response = $this->curlGet($graph_url);
		if (empty($response)) {
			return false;
		}
		
		// decode our response
		$response = json_decode($response, true);
		
		// check response for an error, and if error clear session and return false
		if (!empty($response['error'])) {
			if (self::USE_SESSION) {
				$this->clearSession();
			}
			return false;
		}
		
		return $response;
	}
	
	/**
	 * Redirects to the specified URL with the specified query parameters
	 * 
	 * @param string $url - the url to redirect to
	 * @param array $params (optional) - associative array of query string parameters
	 */
	protected function redirect($url, $params=array()) {
		$redirect_url = $url;
		
		// generate the query string
		if (!empty($params)) {
			$redirect_url .= '?'.http_build_query($params);
		}
		
		echo "<script>top.location.href = '$redirect_url'</script>";
		//header('Location: ' . $redirect_url);
		exit;
	}
	
	/**
	 * Makes a curl get request
	 * 
	 * @param string $url - the url to get from
	 * @param array $params (optional) - the query strinf params
	 */
	protected function curlGet($url, $params=null) {
		if (!empty($params)) {
			$url .= '?'.http_build_query($params);
		}
		$ch = curl_init();
        curl_setopt_array($ch, array(
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_VERBOSE => true
        ));
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
	}
	
	/**
	 * Makes a curl post request
	 * 
	 * @param string $url - the url to post to
	 * @param array $params (optional) - the post params
	 */
	protected function curlPost($url, $params=null) {
		$ch = curl_init();
        curl_setopt_array($ch, array(
            CURLOPT_URL => $url,
            CURLOPT_POSTFIELDS => http_build_query($params),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_VERBOSE => true
        ));
        $result = curl_exec($ch);
        curl_close($ch);
        return $result;
	}
}