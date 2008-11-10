<?php
/**
 * A simple OpenID consumer component for CakePHP.
 * 
 * Requires version 2.1.0 of PHP OpenID library from http://openidenabled.com/php-openid/
 * 
 * To make use of Email Address to URL Transformation (EAUT), you also need the
 * EAUT library: http://code.google.com/p/eaut/
 *
 * To use the MySQLStore, the following steps are required:
 * - get PEAR DB: http://pear.php.net/package/DB
 * - run the openid.sql script to create the required tables 
 * - add Configure::write('Openid.use_database', true); to the file which uses
 *   the OpenID component (e.g. users_controller.php) or to app/config/bootstrap.php
 * - if you want to use a database configuration other than "default", also add
 *   Configure::write('Openid.database_config', 'name_of_database_config');
 * 
 * Copyright (c) by Daniel Hofstetter (http://cakebaker.42dh.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @version			$Revision: 62 $
 * @modifiedby		$LastChangedBy: dho $
 * @lastmodified	$Date: 2008-11-10 15:02:05 +0100 (Mon, 10 Nov 2008) $
 * @license			http://www.opensource.org/licenses/mit-license.php The MIT License
 */
$pathExtra = APP.DS.'vendors'.DS.PATH_SEPARATOR.APP.DS.'vendors'.DS.'pear'.DS.PATH_SEPARATOR.VENDORS.PATH_SEPARATOR.VENDORS.'pear';
$path = ini_get('include_path');
$path = $pathExtra . PATH_SEPARATOR . $path;
ini_set('include_path', $path);

App::import('Vendor', 'consumer', array('file' => 'Auth'.DS.'OpenID'.DS.'Consumer.php'));
App::import('Vendor', 'sreg', array('file' => 'Auth'.DS.'OpenID'.DS.'SReg.php'));

class OpenidComponent extends Object {
	private $controller = null;
	
	public function startUp($controller) {
		$this->controller = $controller;
	}
	
	/**
	 * @throws InvalidArgumentException if an invalid OpenID was provided
	 */
	public function authenticate($openidUrl, $returnTo, $realm, $required = array(), $optional = array()) {
		if (trim($openidUrl) != '') {
			if ($this->isEmail($openidUrl)) {
				$openidUrl = $this->transformEmailToOpenID($openidUrl);
			}

			$consumer = $this->getConsumer();
			$authRequest = $consumer->begin($openidUrl);
		}
		
		if (!isset($authRequest) || !$authRequest) {
		    throw new InvalidArgumentException('Invalid OpenID');
		}
		
		$sregRequest = Auth_OpenID_SRegRequest::build($required, $optional);
		
		if ($sregRequest) {
			$authRequest->addExtension($sregRequest);
		}
		
		if ($authRequest->shouldSendRedirect()) {
			$redirectUrl = $authRequest->redirectUrl($realm, $returnTo);
			
			if (Auth_OpenID::isFailure($redirectUrl)) {
				throw new Exception('Could not redirect to server: '.$redirectUrl->message);
			} else {
				$this->controller->redirect($redirectUrl);
			}
		} else {
			$formId = 'openid_message';
			$formHtml = $authRequest->formMarkup($realm, $returnTo, false , array('id' => $formId));

			if (Auth_OpenID::isFailure($formHtml)) {
				throw new Exception('Could not redirect to server: '.$formHtml->message);
			} else {
				echo '<html><head><title>OpenID transaction in progress</title></head>'.
					 "<body onload='document.getElementById(\"".$formId."\").submit()'>".
					 $formHtml.'</body></html>';
				exit;
			}
		}
	}
	
	public function getResponse($currentUrl) {
		$consumer = $this->getConsumer();
		$response = $consumer->complete($currentUrl, $this->getQuery());
		
		return $response;
	}
	
	private function getConsumer() {
		return new Auth_OpenID_Consumer($this->getStore());
	}

	private function getFileStore() {
		App::import('Vendor', 'filestore', array('file' => 'Auth'.DS.'OpenID'.DS.'FileStore.php'));
		$storePath = TMP.'openid';

		if (!file_exists($storePath) && !mkdir($storePath)) {
		    throw new Exception('Could not create the FileStore directory '.$storePath.'. Please check the effective permissions.');
		}
	
		return new Auth_OpenID_FileStore($storePath);
	}
	
	private function getMySQLStore() {
		App::import('Vendor', 'mysqlstore', array('file' => 'Auth'.DS.'OpenID'.DS.'MySQLStore.php'));
		
		$databaseConfig = Configure::read('Openid.database_config');
		$databaseConfig = ($databaseConfig == null) ? 'default' : $databaseConfig;
		$dataSource = ConnectionManager::getDataSource($databaseConfig);
			
		$dsn = array(
	    	'phptype'  => 'mysql',
	    	'username' => $dataSource->config['login'],
	    	'password' => $dataSource->config['password'],
	    	'hostspec' => $dataSource->config['host'],
	    	'database' => $dataSource->config['database'],
			'port'     => $dataSource->config['port']
		);

		$db = DB::connect($dsn);
		if (PEAR::isError($db)) {
		    die($db->getMessage());
		}

		return new Auth_OpenID_MySQLStore($db);
	}
	
	private function getQuery() {
		$query = Auth_OpenID::getQuery();
		
		// unset the url parameter automatically added by app/webroot/.htaccess 
		// as it causes problems with the verification of the return_to url
    	unset($query['url']);
    	
    	return $query;
	}
	
	private function getStore() {
		$store = null;
		
		if (Configure::read('Openid.use_database') === true) { 
			$store = $this->getMySQLStore();
		} else {	
			$store = $this->getFileStore();
		}
		
		return $store;
	}
	
	private function isEmail($string) {
		return strpos($string, '@');
	}
	
	private function transformEmailToOpenID($email) {
		if (App::import('Vendor', 'emailtoid', array('file' => 'Auth'.DS.'Yadis'.DS.'Email.php'))) {
			return Auth_Yadis_Email_getID($email);
		}
		
		throw new InvalidArgumentException('Invalid OpenID');
	}
}