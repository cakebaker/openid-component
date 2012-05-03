# Changelog

### v2.0.1 (2012-05-03

* Applying fixes from [issue #4](https://github.com/cakebaker/openid-component/pull/4): Using CakePHP 2's request object; and introducing a custom Yadis session handler (`Auth_Yadis_CakeSession`) for a more reliable session handling. Thanks to Brad Koch for the patch.

### v2.0.0 (2012-05-02)

* Switching to Semantic Versioning
* Adding an `$anonymous` parameter to the `authenticate()` method (see [issue #3](https://github.com/cakebaker/openid-component/issues/3))
* Removing support for EAUT

### v2011-01-05

* Adapting component for CakePHP 2.0.0-dev
* Fixing another bug in `isOpenIDResponse()` as it didn't recognize cancel responses (see [issue #2](https://github.com/cakebaker/openid-component/issues#issue/2). Thanks to Sam Mousa for reporting.

### v2010-12-16

* Using `varchar(2047)` for both `server_url` columns. Thanks to [Henrik Gemal](http://gemal.dk/) for reporting.

### v2010-12-08

* Fixing a bug in `isOpenIDResponse() as it didn't recognize POSTed responses from OpenID providers like hyves.nl. Thanks to Sam Mousa for reporting.

### v2010-09-03

* Automatically trim the provided OpenID url in the `authenticate` method

### v2010-08-13

* Fixing a "Class not found" error which occurs when using no models in your controller (i.e. `public $uses = array();` is defined) and the OpenID component setting `use_database` is `true`

### v2010-07-17

* Fixing a bug in `isOpenIDResponse()` which didn't recognize responses from OpenID 1.0 providers like claimid.com and blogger.com

### v2010-05-22

* Fixing a bug with getting the plugin name when the component is used in a plugin on Windows. Thanks to Tim from [Pixelastic](http://pixelastic.com/) for the patch

### v2010-05-19

* Upgrading the bundled PHP OpenID library to version 2.2.2

### v2010-04-13

* Adding (optional) support for Google Apps OpenIDs by integrating the [php-openid-apps-discovery](http://code.google.com/p/php-openid-apps-discovery/) library

### v2009-12-12

* Moving code to Git/GitHub
* Adding support for Attribute Exchange (AX)
* Changing the API of `authenticate` slightly, the parameters `$required` and `$optional` have been replaced with a `$dataFields` parameter. Old: `$this->Openid->authenticate($openid, $returnTo, $realm, array('email'), array('nickname'));`, new: `$this->Openid->authenticate($openid, $returnTo, $realm, array('sreg_required' => array('email'), 'sreg_optional' => array('nickname')));`

### v2009-09-26

* "Fixing" an issue in the PHP OpenID library which causes a blank page on PHP 5.3.

### v2009-08-17

* Including PHP OpenID and PEAR DB in the package for convenience purposes so you no longer have to download them separately
* The settings necessary for when you want to store the OpenID data in the database are now specified in the `$components` array. `Configure::write('Openid.use_database', true);` and `Configure::write('Openid.database_config', 'name_of_database_config');` are no longer supported!
* Fixing a bug that caused a `Class not found` error when both the component and the "vendors" files are in a plugin

### v2009-05-04

* Adding a public `cleanup()` method

### v2008-11-10

* Applying patch from [Florian Fritz](http://florianfritz.de/) which eliminates the need to modify the PHP OpenID library

### v2008-08-27

* Adding support for MySQL

### v2008-08-09

* Adding support for "Email Address to URL Transformation" (EAUT)

### v2008-06-09

* Renaming the parameter of `OpenidComponent::getResponse()` to use the same term as is used in version 2.1.0 of the PHP OpenID library

### v2008-06-06

* Minor changes to avoid deprecation messages with CakePHP 1.2 RC1

### v2008-02-06

* Component updated to work with version 2.0.0 of the PHP OpenID library

### v2007-03-02

* Fixing "No XML parser" error by providing a slightly modified version of the PHP OpenID library

### v2007-02-23

* Fixing a bug with path separators on Windows
