<?php
/**
 * A simple OpenID consumer component for CakePHP.
 * 
 * Depends on version 2.2.2 of the PHP OpenID library (http://openidenabled.com/php-openid/)
 * 
 * To use the MySQLStore, the following steps are required:
 * - run the openid.sql script to create the required tables 
 * - use one of the following config settings when adding the component to the $components array of your controller(s):
 *     public $components = array('Openid' => array('use_database' => true)); // uses the "default" database configuration
 *     public $components = array('Openid' => array('database_config' => 'name_of_database_config'));
 * 
 * To accept Google Apps OpenIDs, use the following config setting:
 *     public $components = array('Openid' => array('accept_google_apps' => true));
 *
 * To make use of Email Address to URL Transformation (EAUT), you also need the
 * EAUT library: http://code.google.com/p/eaut/
 *
 * Copyright (c) by Daniel Hofstetter (daniel.hofstetter@42dh.com, http://cakebaker.42dh.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 */
class OpenidComponent extends Object {
    private $controller = null;
    private $importPrefix = '';
    private $useDatabase = false;
    private $databaseConfig = 'default';
    private $acceptGoogleApps = false;
    const AX = 'ax';
    const SREG_REQUIRED = 'sreg_required';
    const SREG_OPTIONAL = 'sreg_optional';

    public function __construct() {
        parent::__construct();

        $pathToVendorsFolder = $this->getPathToVendorsFolderWithOpenIDLibrary();

        if ($pathToVendorsFolder == '') {
            exit('Unable to find the PHP OpenID library');
        }

        if ($this->isPathWithinPlugin($pathToVendorsFolder)) {
            $this->importPrefix = $this->getPluginName() . '.';
        }

        $this->addToIncludePath($pathToVendorsFolder);
        $this->importCoreFilesFromOpenIDLibrary();
    }

    public function initialize($controller, $settings) {
        if (isset($settings['use_database'])) {
            $this->useDatabase = $settings['use_database'];
        }

        if (isset($settings['database_config'])) {
            $this->databaseConfig = $settings['database_config'];
            $this->useDatabase = true;
        }

        if (isset($settings['accept_google_apps'])) {
            $this->acceptGoogleApps = $settings['accept_google_apps'];
        }
    }

    public function startUp($controller) {
        $this->controller = $controller;
    }

    /**
     * @param $dataFields An associative array, valid keys are "sreg_required" and "sreg_optional" for
     * SReg (simple registration), and "ax" for attribute exchange.
     * Examples:
     *   $dataFields = array('sreg_required' => array('email'), 'sreg_optional' => array('nickname'));
     *   $dataFields = array('ax' => array(Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson')));
     * @throws InvalidArgumentException if an invalid OpenID was provided
     */
    public function authenticate($openidUrl, $returnTo, $realm, $dataFields = array()) {
        $defaults = array(self::AX => array(), self::SREG_REQUIRED => array(), self::SREG_OPTIONAL => array());
        $dataFields = array_merge($defaults, $dataFields);
        $openidUrl = trim($openidUrl);

        if ($openidUrl != '') {
            if ($this->isEmail($openidUrl)) {
                $openidUrl = $this->transformEmailToOpenID($openidUrl);
            }

            $consumer = $this->getConsumer();
            $authRequest = $consumer->begin($openidUrl);
        }

        if (!isset($authRequest) || !$authRequest) {
            throw new InvalidArgumentException('Invalid OpenID');
        }

        $this->addSReg($authRequest, $dataFields);
        $this->addAX($authRequest, $dataFields);

        if ($authRequest->shouldSendRedirect()) {
            $this->redirect($authRequest, $returnTo, $realm);
        } else {
            $this->showFormWithAutoSubmit($authRequest, $returnTo, $realm);
        }
    }

    /**
     * Removes expired associations and nonces.
     *
     * This method is not called in the normal operation of the component. It provides a way
     * for store admins to keep their storage from filling up with expired data.
     */
    public function cleanup() {
        $store = $this->getStore();

        return $store->cleanup();
    }

    public function getResponse($currentUrl) {
        $consumer = $this->getConsumer();
        $response = $consumer->complete($currentUrl, $this->getQuery());

        return $response;
    }

    public function isOpenIDResponse() {
        if ($this->isOpenIDResponseViaGET() || $this->isOpenIDResponseViaPOST()) {
            return true;
        }

        return false;
    }

    private function addAX($authRequest, $dataFields) {
        if (count($dataFields[self::AX]) > 0) {
            $ax = new Auth_OpenID_AX_FetchRequest;

            foreach($dataFields[self::AX] as $attribute){
                $ax->add($attribute);
            }

            $authRequest->addExtension($ax);
        }
    }

    private function addSReg($authRequest, $dataFields) {
        $sregRequest = Auth_OpenID_SRegRequest::build($dataFields[self::SREG_REQUIRED], $dataFields[self::SREG_OPTIONAL]);

        if ($sregRequest) {
            $authRequest->addExtension($sregRequest);
        }
    }

    private function addToIncludePath($pathToVendorsFolder) {
        $pathExtra = $pathToVendorsFolder . PATH_SEPARATOR . $pathToVendorsFolder . 'pear' . DS;
        $path = ini_get('include_path');
        $path = $pathExtra . PATH_SEPARATOR . $path;
        ini_set('include_path', $path);
    }

    private function getConsumer() {
        $consumer = new Auth_OpenID_Consumer($this->getStore());

        if ($this->acceptGoogleApps) {
            new GApps_OpenID_Discovery($consumer);
        }

        return $consumer;
    }

    private function getFileStore() {
        App::import('Vendor', $this->importPrefix.'filestore', array('file' => 'Auth'.DS.'OpenID'.DS.'FileStore.php'));
        $storePath = TMP.'openid';

        if (!file_exists($storePath) && !mkdir($storePath)) {
            throw new Exception('Could not create the FileStore directory '.$storePath.'. Please check the effective permissions.');
        }

        return new Auth_OpenID_FileStore($storePath);
    }

    private function getMySQLStore() {
        App::import('Vendor', $this->importPrefix.'peardb', array('file' => 'pear'.DS.'DB.php'));
        App::import('Vendor', $this->importPrefix.'mysqlstore', array('file' => 'Auth'.DS.'OpenID'.DS.'MySQLStore.php'));
        App::import('Core', 'ConnectionManager');
        $dataSource = ConnectionManager::getDataSource($this->databaseConfig);

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

    private function getPathToVendorsFolderWithOpenIDLibrary() {
        $pathToVendorsFolder = '';

        if ($this->isPathWithinPlugin(__FILE__)) {
            $pluginName = $this->getPluginName();

            if (file_exists(APP.'plugins'.DS.$pluginName.DS.'vendors'.DS.'Auth')) {
                $pathToVendorsFolder = APP.'plugins'.DS.$pluginName.DS.'vendors'.DS;
            }
        }

        if ($pathToVendorsFolder == '') {
            if (file_exists(APP.'vendors'.DS.'Auth')) {
                $pathToVendorsFolder = APP.'vendors'.DS;
            } elseif (file_exists(VENDORS.'Auth')) {
                $pathToVendorsFolder = VENDORS;
            }
        }

        return $pathToVendorsFolder;
    }

    private function getPluginName() {
        $result = array();
        $ds = (Folder::isWindowsPath(__FILE__)) ? '\\\\' : DS;

        if (preg_match('#'.$ds.'plugins'.$ds.'(.*)'.$ds.'controllers#', __FILE__, $result)) {
            return $result[1];
        }

        return false;
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

        if ($this->useDatabase) {
            $store = $this->getMySQLStore();
        } else {
            $store = $this->getFileStore();
        }

        return $store;
    }

    private function importCoreFilesFromOpenIDLibrary() {
        App::import('Vendor', $this->importPrefix.'consumer', array('file' => 'Auth'.DS.'OpenID'.DS.'Consumer.php'));
        App::import('Vendor', $this->importPrefix.'sreg', array('file' => 'Auth'.DS.'OpenID'.DS.'SReg.php'));
        App::import('Vendor', $this->importPrefix.'ax', array('file' => 'Auth'.DS.'OpenID'.DS.'AX.php'));
        App::import('Vendor', $this->importPrefix.'google', array('file' => 'Auth'.DS.'OpenID'.DS.'google_discovery.php'));
    }

    private function isEmail($string) {
        return strpos($string, '@');
    }

    private function isOpenIDResponseViaGET() {
        return (isset($this->controller->params['url']['openid_mode']));
    }

    private function isOpenIDResponseViaPOST() {
        return (isset($this->controller->params['form']['openid_mode']));
    }

    private function isPathWithinPlugin($path) {
        return strpos($path, DS.'plugins'.DS) ? true : false;
    }

    private function redirect($request, $returnTo, $realm) {
        $redirectUrl = $request->redirectUrl($realm, $returnTo);

        if (Auth_OpenID::isFailure($redirectUrl)) {
            throw new Exception('Could not redirect to server: '.$redirectUrl->message);
        }

        $this->controller->redirect($redirectUrl);
    }

    private function showFormWithAutoSubmit($request, $returnTo, $realm) {
        $formId = 'openid_message';
        $formHtml = $request->formMarkup($realm, $returnTo, false , array('id' => $formId));

        if (Auth_OpenID::isFailure($formHtml)) {
            throw new Exception('Could not redirect to server: '.$formHtml->message);
        }

        echo '<html><head><title>' . __('OpenID Authentication Redirect', true) . '</title></head>'.
             "<body onload='document.getElementById(\"".$formId."\").submit()'>".
             $formHtml.'</body></html>';
        exit;
    }

    private function transformEmailToOpenID($email) {
        if (App::import('Vendor', $this->importPrefix.'emailtoid', array('file' => 'Auth'.DS.'Yadis'.DS.'Email.php'))) {
            return Auth_Yadis_Email_getID($email);
        }

        throw new InvalidArgumentException('Invalid OpenID');
    }
}
