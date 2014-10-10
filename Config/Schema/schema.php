<?php
/**
 *
 * @author Jason Burgess <jason@notplugged.in>
 * @version 1.1
 *
 */
class OpenIdSchema extends CakeSchema {

	public $oid_associations = array(
			'server_url' => array(
					'type' => 'string',
					'null' => false,
					'limit' => 2047,
					'key' => 'primary',
					'collate' => 'utf8_general_ci',
					'charset' => 'utf8'),
			'handle' => array(
					'type' => 'string',
					'null' => false,
					'limit' => 255,
					'key' => 'primary'),
			'secret' => array('type' => 'binary', 'null' => false),
			'issued' => array('type' => 'integer', 'null' => false),
			'lifetime' => array('type' => 'integer', 'null' => false),
			'assoc_type' => array('type' => 'string', 'null' => false, 'limit' => 64),
			'indexes' => array(
					'PRIMARY' => array(
							'column' => array('`server_url`(255)', 'handle'),
							'unique' => 1)),
			'tableParameters' => array(
					'charset' => 'utf8',
					'collate' => 'utf8_general_ci',
					'engine' => 'InnoDB'));

	public $oid_nonces = array(
			'server_url' => array(
					'type' => 'string',
					'null' => false,
					'limit' => 2047,
					'key' => 'primary',
					'collate' => 'utf8_general_ci',
					'charset' => 'utf8'),
			'timestamp' => array('type' => 'integer', 'null' => false),
			'salt' => array('type' => 'string', 'null' => false, 'length' => 40),
			'indexes' => array(
					'PRIMARY' => array('column' => array('`server_url`(255)', 'timestamp', 'salt'))),
			'tableParameters' => array(
					'charset' => 'utf8',
					'collate' => 'utf8_general_ci',
					'engine' => 'InnoDB'));
}
