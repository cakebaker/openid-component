<?php
/**
 * Yadis CakeSession Handler
 *
 * Since cake has its own implementation of sessions, we route directly through
 * the CakeSession class so as to avoid unexpected errors.
 */
class Auth_Yadis_CakeSession extends Auth_Yadis_PHPSession {
    private $prefix = 'Yadis';
    
    /**
     * Set a session key/value pair.
     *
     * @param string $name The name of the session key to add.
     * @param string $value The value to add to the session.
     */
    function set($name, $value)
    {
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
    function get($name, $default=null)
    {
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
    function del($name)
    {
        CakeSession::delete($this->prefix . '.' . $name);
    }

    /**
     * Return the contents of the session in array form.
     */
    function contents()
    {
        return CakeSession::read($this->prefix);
    }
}

