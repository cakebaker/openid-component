# OpenID component for CakePHP

## Purpose

An OpenID component for CakePHP 2.x. Supports SReg (simple registration extension) and AX (attribute exchange). For CakePHP 1.x, please check out the [`cakephp_1.x` branch](https://github.com/cakebaker/openid-component/tree/cakephp_1.x).

## Installation

* Copy the file `Controller/Component/OpenidComponent.php` to the `Controller/Component` folder of your application or plugin
* Copy the `Vendor/Auth` folder to one of your `vendors` folders (`vendors`, `app/Vendor`, or `app/Plugin/<pluginname>/Vendor`)
* Add the component to the `$components` array of your controller(s)
* On Windows, add `define('Auth_OpenID_RAND_SOURCE', null)` to `app/Config/bootstrap.php` to use an insecure random number generator because the default random number generator used (`/dev/urandom`) is not available on Windows

### Using the MySQLStore (optional)

By default, the OpenID component stores all data in `app/tmp/openid`. To store those data in a MySQL database, please follow these steps:

* Copy the `Vendor/pear` folder to one of your `vendors` folders
* Run the `openid.sql` script, available in `Config/sql`, to create the necessary tables
* Configure the component to use a database by following one of these two steps:
   * To use the `default` database configuration defined in `app/Config/database.php`: `public $components = array('Openid' => array('use_database' => true));`
   * To use another database configuration: `public $components = array('Openid' => array('database_config' => 'name_of_database_config'));`

### Accepting Google Apps OpenIDs (optional)

By default, the OpenID component doesn't accept Google Apps OpenIDs. The reason it's disabled by default is that it introduces an additional request to Google every time the authentication process is started.

To enable support for Google Apps OpenIDs, use the following config setting: `public $components = array('Openid' => array('accept_google_apps' => true));`

## Example application

There is a very simple example application available to show you how to use the OpenID component. Its source code is available in the [openid-component-example repo](https://github.com/cakebaker/openid-component-example), and you can see the application in action on http://openid-example.42dh.com.

## Example usage

First, we need a login form:

```php
<?php
// app/View/Users/login.ctp
if (isset($error)) {
      echo '<p class="error">'.$error.'</p>';
}
echo $this->Form->create('User', array('type' => 'post', 'action' => 'login'));
echo $this->Form->input('OpenidUrl.openid', array('label' => false));
echo $this->Form->end('Login');
?>
```

Next, we have to write a controller to handle this form. Our controller has to perform the following tasks: show the login form, redirect the user to the OpenID provider after he submitted the login form, and last, but not least, handle the response from the OpenID provider.

```php
<?php
// app/Controller/UsersController.php
class UsersController extends AppController {
    public $components = array('Openid');
    public $uses = array();

    public function login() {
        $realm = 'http://' . $_SERVER['HTTP_HOST'];
        $returnTo = $realm . '/users/login';

        if ($this->request->isPost() && !$this->Openid->isOpenIDResponse()) {
            try {
                $this->Openid->authenticate($this->data['OpenidUrl']['openid'], $returnTo, $realm);
            } catch (InvalidArgumentException $e) {
                $this->set('error', 'Invalid OpenID');
            } catch (Exception $e) {
                $this->set('error', $e->getMessage());
            }
        } elseif ($this->Openid->isOpenIDResponse()) {
            $response = $this->Openid->getResponse($returnTo);

            if ($response->status == Auth_OpenID_CANCEL) {
                $this->set('error', 'Verification cancelled');
            } elseif ($response->status == Auth_OpenID_FAILURE) {
                $this->set('error', 'OpenID verification failed: '.$response->message);
            } elseif ($response->status == Auth_OpenID_SUCCESS) {
                echo 'successfully authenticated!';
                exit;
            }
        }
    }
}
```
When testing this example, your OpenID provider might show you a warning that your site couldn't be verified (as far as I know only AOL shows such a warning). To get rid of this warning, please see the article [Enabling your application for return URL verification](http://cakebaker.42dh.com/2008/03/18/enabling-your-application-for-return-url-verification/).

### Using the Simple Registration Extension (SReg)

The [Simple Registration Extension](http://openid.net/specs/openid-simple-registration-extension-1_0.html) allows you to retrieve nine commonly requested pieces of information: nickname, email, fullname, dob (date of birth), gender, postcode, country, language, and timezone. Please be aware that some OpenID providers (for example, Google) don't support SReg.

```php
<?php
// app/Controller/UsersController.php
class UsersController extends AppController {
    public $components = array('Openid');

    public function login() {
        $realm = 'http://'.$_SERVER['HTTP_HOST'];
        $returnTo = $realm . '/users/login';

        if ($this->request->isPost() && !$this->Openid->isOpenIDResponse()) {
            $this->makeOpenIDRequest($this->data['OpenidUrl']['openid'], $returnTo, $realm);
        } elseif ($this->Openid->isOpenIDResponse()) {
            $this->handleOpenIDResponse($returnTo);
        }
    }

    private function makeOpenIDRequest($openid, $returnTo, $realm) {
        $required = array('email');
        $optional = array('nickname');
        $this->Openid->authenticate($openid, $returnTo, $realm, array('sreg_required' => $required, 'sreg_optional' => $optional));
    }

    private function handleOpenIDResponse($returnTo) {
        $response = $this->Openid->getResponse($returnTo);

        if ($response->status == Auth_OpenID_SUCCESS) {
            $sregResponse = Auth_OpenID_SRegResponse::fromSuccessResponse($response);
            $sregContents = $sregResponse->contents();

            if ($sregContents) {
                if (array_key_exists('email', $sregContents)) {
                    debug($sregContents['email']);
                }
                if (array_key_exists('nickname', $sregContents)) {
                    debug($sregContents['nickname']);
                }
            }
        }
    }
}
```

### Using Attribute Exchange (AX)

[Attribute Exchange](http://openid.net/specs/openid-attribute-exchange-1_0.html) allows you to retrieve identity information from the OpenID provider, if supported. http://www.axschema.org/types contains a list with possible attribute names, though only a small subset is usually supported by the OpenID providers.

```php
<?php
// app/Controller/UsersController.php
class UsersController extends AppController {
    public $components = array('Openid');

    public function login() {
        $realm = 'http://'.$_SERVER['HTTP_HOST'];
        $returnTo = $realm . '/users/login';

        if ($this->request->isPost() && !$this->Openid->isOpenIDResponse()) {
            $this->makeOpenIDRequest($this->data['OpenidUrl']['openid'], $returnTo, $realm);
        } elseif ($this->Openid->isOpenIDResponse()) {
            $this->handleOpenIDResponse($returnTo);
        }
    }

    private function makeOpenIDRequest($openid, $returnTo, $realm) {
        // some OpenID providers (e.g. MyOpenID) use 'schema.openid.net' instead of 'axschema.org'
        $attributes[] = Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson', 1, true, 'fullname');
        $this->Openid->authenticate($openid, $returnTo, $realm, array('ax' => $attributes));
    }

    private function handleOpenIDResponse($returnTo) {
        $response = $this->Openid->getResponse($returnTo);

        if ($response->status == Auth_OpenID_SUCCESS) {
            $axResponse = Auth_OpenID_AX_FetchResponse::fromSuccessResponse($response);

            if ($axResponse) {
                debug($axResponse->get('http://axschema.org/namePerson'));
                debug($axResponse->getSingle('http://axschema.org/namePerson'));
            }
        }
    }
}
```

## Troubleshooting

If you encounter signature validation errors, it could be because of bugs in the GMP math library. In this case, add the following constant to `app/config/bootstrap.php`: `define('Auth_OpenID_BUGGY_GMP', true);`

## Contact

Feel free to contact me via Twitter ([@dhofstet](https://twitter.com/dhofstet)) or by email (daniel.hofstetter@42dh.com) if you have any questions or feedback.

## License

The OpenID component is licensed under the MIT license.
