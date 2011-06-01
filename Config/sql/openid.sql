-- Extracted from Auth/OpenID/MySQLStore.php

CREATE TABLE oid_associations (
	server_url VARCHAR(2047) NOT NULL,
	handle VARCHAR(255) NOT NULL,
	secret BLOB NOT NULL,
	issued INTEGER NOT NULL,
	lifetime INTEGER NOT NULL,
	assoc_type VARCHAR(64) NOT NULL,
	PRIMARY KEY (server_url(255), handle)
) ENGINE=InnoDB;

CREATE TABLE oid_nonces (
	server_url VARCHAR(2047) NOT NULL,
	timestamp INTEGER NOT NULL,
	salt CHAR(40) NOT NULL,
	UNIQUE (server_url(255), timestamp, salt)
) ENGINE=InnoDB;
