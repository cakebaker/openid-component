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
 * Copyright (c) by Daniel Hofstetter (daniel.hofstetter@42dh.com, http://cakebaker.42dh.com)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 */
class OpenidComponent extends Component {
    private $controller = null;
    private $importPrefix = '';
    private $useDatabase = false;
    private $databaseConfig = 'default';
    private $acceptGoogleApps = false;
    const AX = 'ax';
    const SREG_REQUIRED = 'sreg_required';
    const SREG_OPTIONAL = 'sreg_optional';

    public function __construct(ComponentCollection $collection, $settings = array()) {
        parent::__construct($collection, $settings);
        $this->handleSettings($settings);

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

    public function startUp(Controller $controller) {
        $this->controller = $controller;
    }

    /**
     * @param $dataFields An associative array, valid keys are "sreg_required" and "sreg_optional" for
     * SReg (simple registration), and "ax" for attribute exchange.
     * Examples:
     *   $dataFields = array('sreg_required' => array('email'), 'sreg_optional' => array('nickname'));
     *   $dataFields = array('ax' => array(Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson')));
     *
     * @param bool $anonymous True if the OpenID request is to be sent
     * to the server without any identifier information.  Use this
     * when you want to transport data but don't want to do OpenID
     * authentication with identifiers.
     * NOTE: $openidUrl need to be the OpenID provider url for proper discovery
     *
     * @throws InvalidArgumentException if an invalid OpenID was provided
     */
    public function authenticate($openidUrl, $returnTo, $realm, $dataFields = array(), $anonymous = false) {
        $defaults = array(self::AX => array(), self::SREG_REQUIRED => array(), self::SREG_OPTIONAL => array());
        $dataFields = array_merge($defaults, $dataFields);
        $openidUrl = trim($openidUrl);

        if ($openidUrl != '') {
            $consumer = $this->getConsumer();
            $authRequest = $consumer->begin($openidUrl, $anonymous);
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
        $consumer = new Auth_OpenID_Consumer($this->getStore(), new Auth_Yadis_CakeSession());

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
        App::uses('ConnectionManager', 'Model');
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

            if (file_exists(APP.'Plugin'.DS.$pluginName.DS.'Vendor'.DS.'Auth')) {
                $pathToVendorsFolder = APP.'Plugin'.DS.$pluginName.DS.'Vendor'.DS;
            }
        }

        if ($pathToVendorsFolder == '') {
            if (file_exists(APP.'Vendor'.DS.'Auth')) {
                $pathToVendorsFolder = APP.'Vendor'.DS;
            } elseif (file_exists(VENDORS.'Auth')) {
                $pathToVendorsFolder = VENDORS;
            }
        }

        return $pathToVendorsFolder;
    }

    private function getPluginName() {
        $result = array();
        App::uses('Folder', 'Utility');
        $ds = (Folder::isWindowsPath(__FILE__)) ? '\\\\' : DS;

        if (preg_match('#'.$ds.'Plugin'.$ds.'(.*)'.$ds.'Controller#', __FILE__, $result)) {
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

    private function handleSettings($settings) {
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

    private function importCoreFilesFromOpenIDLibrary() {
        App::import('Vendor', $this->importPrefix.'consumer', array('file' => 'Auth'.DS.'OpenID'.DS.'Consumer.php'));
        App::import('Vendor', $this->importPrefix.'sreg', array('file' => 'Auth'.DS.'OpenID'.DS.'SReg.php'));
        App::import('Vendor', $this->importPrefix.'ax', array('file' => 'Auth'.DS.'OpenID'.DS.'AX.php'));
        App::import('Vendor', $this->importPrefix.'google', array('file' => 'Auth'.DS.'OpenID'.DS.'google_discovery.php'));
    }

    private function isOpenIDResponseViaGET() {
        return (isset($this->controller->request->query['openid_mode']));
    }

    private function isOpenIDResponseViaPOST() {
        return (isset($this->controller->request->data['openid_mode']));
    }

    private function isPathWithinPlugin($path) {
        return strpos($path, DS.'Plugin'.DS) ? true : false;
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

        echo '<html><head><title>' . __('OpenID Authentication Redirect') . '</title></head>'.
             "<body onload='document.getElementById(\"".$formId."\").submit()'>".
             $formHtml.'</body></html>';
        exit;
    }
}

/**
 * Yadis CakeSession Handler, implements the "interface" defined by Auth_Yadis_PHPSession in Vendor/Auth/Yadis/Manager.php
 *
 * Since cake has its own implementation of sessions, we route directly through
 * the CakeSession class so as to avoid unexpected errors.
 */
class Auth_Yadis_CakeSession {
    private $prefix = 'Yadis';

    /**
     * Set a session key/value pair.
     *
     * @param string $name The name of the session key to add.
     * @param string $value The value to add to the session.
     */
    public function set($name, $value) {
        CakeSession::write($this->prefix . '.' . $name, $value);
    }

    /**
     * Get a key's value from the session.
     *
     * @param string $name The name of the key to retrieve.
     * @param string $default The optional value to return if the key
     * is not found in the session.
     * @return string $result The key's value in the session or
     * $default if it isn't found.
     */
    public function get($name, $default = null) {
        $value = CakeSession::read($this->prefix . '.' . $name);

        if ($value !== null) {
            return $value;
        } else {
            return $default;
        }
    }

    /**
     * Remove a key/value pair from the session.
     *
     * @param string $name The name of the key to remove.
     */
    public function del($name) {
        CakeSession::delete($this->prefix . '.' . $name);
    }

    /**
     * Return the contents of the session in array form.
     */
    public function contents() {
        return CakeSession::read($this->prefix);
    }
}
