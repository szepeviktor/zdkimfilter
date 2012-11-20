# 

CREATE DATABASE IF NOT EXISTS zfilter_test;

# GRANT SELECT, INSERT, UPDATE, EXECUTE ON zfilter_test.* TO 'zfilter'@'localhost'

USE zfilter_test;
DROP TABLE IF EXISTS domain;
CREATE TABLE domain (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain VARCHAR(63)  NOT NULL,
  recv INT UNSIGNED NOT NULL DEFAULT 0,
  sent INT UNSIGNED NOT NULL DEFAULT 0,
  whitelisted TINYINT NOT NULL DEFAULT 0,
  since TIMESTAMP NOT NULL DEFAULT NOW(),
  last TIMESTAMP NOT NULL DEFAULT 0,
  INDEX by_dom(domain(16))
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

DROP TABLE IF EXISTS msg_ref;
CREATE TABLE msg_ref (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  message_in INT UNSIGNED NOT NULL COMMENT 'Foreign key to message_in',
  domain INT UNSIGNED NOT NULL COMMENT 'Foreign key to domain',
  reputation INT NOT NULL,
  auth SET ('author', 'spf_helo', 'spf', 'dkim', 'vbr', 'rep', 'rep_s') NOT NULL,
  vbr ENUM ('spamhaus', 'who_else') NOT NULL,
  INDEX by_dom_msg(domain, message_in)
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

DROP TABLE IF EXISTS message_in;
CREATE TABLE message_in (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ino BIGINT UNSIGNED NOT NULL,
  mtime BIGINT UNSIGNED NOT NULL,
  pid  BIGINT UNSIGNED NOT NULL,
  ip BINARY(4) NOT NULL COMMENT 'Ok for IPv4.  For IPv6 use VARBINARY(16)',
  date VARCHAR(63),
  message_id VARCHAR(63),
  content_type VARCHAR(63) NOT NULL DEFAULT 'text/plain',
  content_encoding VARCHAR(63) NOT NULL DEFAULT '7bit',
  received_count SMALLINT UNSIGNED NOT NULL,
  signatures_count SMALLINT UNSIGNED NOT NULL,
  mailing_list TINYINT NOT NULL DEFAULT 0,
  score SMALLINT DEFAULT NULL COMMENT 'NULL if not tested',
  UNIQUE KEY (mtime, pid, ino)
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

DROP TABLE IF EXISTS user;
CREATE TABLE user (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  addr VARCHAR(63) NOT NULL,
  INDEX by_addr(addr(16))
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

DROP TABLE IF EXISTS message_out;
CREATE TABLE message_out (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ino BIGINT UNSIGNED NOT NULL,
  mtime BIGINT UNSIGNED NOT NULL,
  pid  BIGINT UNSIGNED NOT NULL,
  user INT UNSIGNED NOT NULL COMMENT 'Foreign key to user',
  date VARCHAR(63),
  message_id VARCHAR(63),
  content_type VARCHAR(63) NOT NULL DEFAULT 'text/plain',
  content_encoding VARCHAR(63) NOT NULL DEFAULT '7bit',
  UNIQUE KEY (mtime, pid, ino)
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

DROP TABLE IF EXISTS msg_out_ref;
CREATE TABLE msg_out_ref (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  message_out INT UNSIGNED NOT NULL COMMENT 'Foreign key to message_out',
  domain INT UNSIGNED NOT NULL COMMENT 'Foreign key to domain',
  INDEX by_dom_msg_out(domain, message_out)
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;


DROP PROCEDURE IF EXISTS recv_from_domain;

delimiter //
CREATE PROCEDURE recv_from_domain (
	IN m_ref INT UNSIGNED,
	IN dname VARCHAR(255),
	IN m_auth SET ('author', 'spf_helo', 'spf', 'dkim', 'vbr', 'rep', 'rep_s'),
	IN vbr_mv VARCHAR(255),
	IN rep INT)
#	COMMENT 'Called by db_sql_insert_msg_ref: Insert/update domain, insert msg_ref'
	MODIFIES SQL DATA
BEGIN
	DECLARE d_id INT UNSIGNED;
	DECLARE d_whit TINYINT;
	DECLARE Empty_set CONDITION FOR 1329;
	DECLARE CONTINUE HANDLER FOR Empty_set
		BEGIN
			INSERT INTO domain SET domain = dname;
			SELECT LAST_INSERT_ID() INTO d_id;
			SET d_whit = 0;
		END;
	SELECT id, whitelisted INTO d_id, d_whit FROM domain WHERE domain = dname;
	IF d_whit < 1 AND FIND_IN_SET('dkim', m_auth) THEN
		# whitelisted=1 just affects the order in which to try signature validation
		UPDATE domain SET whitelisted = 1, recv = recv + 1, last = NOW() WHERE id = d_id;
	ELSE
		UPDATE domain SET recv = recv + 1, last = NOW() WHERE id = d_id;
	END IF;
	INSERT INTO msg_ref SET message_in = m_ref, domain = d_id, auth = m_auth,
		reputation = rep,
		vbr = IF(STRCMP(vbr_mv, 'dwl.spamhaus.org') = 0, '(spamhaus)', '()');
END //

DROP PROCEDURE IF EXISTS sent_message //

CREATE PROCEDURE sent_message (
	IN u_addr VARCHAR(255),
	IN m_ino BIGINT UNSIGNED,
	IN m_mtime BIGINT UNSIGNED,
	IN m_pid BIGINT UNSIGNED,
	IN m_date VARCHAR(63),
	IN m_id VARCHAR(63),
	IN m_ct VARCHAR(63),
	IN m_ce VARCHAR(63))
#	COMMENT 'Called by db_sql_select_user: Insert/update user, insert message_out'
	MODIFIES SQL DATA
BEGIN
	DECLARE u_id INT UNSIGNED;
	DECLARE Empty_set CONDITION FOR 1329;
	DECLARE CONTINUE HANDLER FOR Empty_set
		BEGIN
			INSERT INTO user SET addr = u_addr;
			SELECT LAST_INSERT_ID() INTO u_id;
		END;
	SELECT id INTO u_id FROM user WHERE addr = u_addr LIMIT 1;
	INSERT INTO message_out SET ino = m_ino, mtime = m_mtime, pid = m_pid,
		user = u_id, date = m_date, message_id = m_id,
		content_type = m_ct, content_encoding = m_ce;
	SELECT LAST_INSERT_ID(); # result, goes into u_ref
END //

DROP PROCEDURE IF EXISTS sent_to_domain //

CREATE PROCEDURE sent_to_domain (
	IN u_ref INT UNSIGNED,
	IN dname VARCHAR(255))
#	COMMENT 'Called by db_sql_insert_target_ref: Insert/update domain, insert msg_out_ref'
	MODIFIES SQL DATA
BEGIN
	DECLARE d_id INT UNSIGNED;
	DECLARE d_whit TINYINT;
	DECLARE Empty_set CONDITION FOR 1329;
	DECLARE CONTINUE HANDLER FOR Empty_set
		BEGIN
			INSERT INTO domain SET domain = dname;
			SELECT LAST_INSERT_ID() INTO d_id;
			SET d_whit = 0;
		END;
	SELECT id, whitelisted INTO d_id, d_whit FROM domain WHERE domain = dname;
	IF d_whit < 2 THEN
		# whitelisted=2 prevents ADSP discard; whitelisted=3 is not used yet
		UPDATE domain SET whitelisted = 2, sent = sent + 1, last = NOW() WHERE id = d_id;
	ELSE
		UPDATE domain SET sent = sent + 1, last = NOW() WHERE id = d_id;
	END IF;
	INSERT INTO msg_out_ref SET message_out = u_ref, domain = d_id;
END //

delimiter ;

# example query, to see who signed what messages:
SELECT INET_NTOA(CONV(HEX(m.ip),16,10)), m.date, FROM_UNIXTIME(m.mtime), d.domain, r.auth
FROM msg_ref AS r, message_in AS m, domain AS d
WHERE r.domain=d.id AND r.message_in=m.id AND FIND_IN_SET('dkim', r.auth)


# how many new domains have been added today?
SELECT COUNT(*) FROM domain WHERE since > NOW() - INTERVAL 1 DAY

# how many messages did each of them send?
SELECT d.id, d.domain, r.auth, COUNT(*) AS cnt
FROM domain AS d, msg_ref AS r, message_in AS m
WHERE d.id = r.domain AND r.message_in = m.id AND d.since > NOW() - INTERVAL 1 DAY
GROUP BY d.id, r.auth ORDER BY cnt DESC LIMIT 10

# how many messages did they send as a whole?
SELECT count(*)
FROM domain AS d, msg_ref AS r, message_in AS m
WHERE d.id = r.domain AND r.message_in = m.id AND d.since > NOW() - INTERVAL 1 DAY


# delete incoming messages older than 1 month
DELETE r, m FROM msg_ref AS r, message_in AS m
WHERE r.message_in = m.id AND m.mtime < UNIX_TIMESTAMP(NOW() - INTERVAL 1 MONTH)

# find domains having been orphaned that way
SELECT l.* FROM domain AS l LEFT JOIN msg_ref AS r ON r.domain = l.id
WHERE r.domain IS NULL AND l.recv > 0


# delete outgoing messages older than 1 month
DELETE r, m FROM msg_out_ref AS r, message_out AS m
WHERE r.message_out = m.id AND m.mtime < UNIX_TIMESTAMP(NOW() - INTERVAL 1 MONTH)

# find domains having been orphaned that way
SELECT l.* FROM domain AS l LEFT JOIN msg_out_ref AS r ON r.domain = l.id
WHERE r.domain IS NULL AND l.sent > 0


# find which users sent how many messages to a given list of domains
SELECT d.domain, COUNT(*) AS cnt, u.addr
FROM domain AS d, msg_out_ref AS r, message_out AS m, user AS u
WHERE d.id = r.domain AND r.message_out = m.id AND m.user = u.id AND
d.id IN (1,2,3,4,5) GROUP BY u.id

SELECT d.domain, COUNT(*) AS cnt, u.addr
FROM domain AS d, msg_out_ref AS r, message_out AS m, user AS u
WHERE d.id = r.domain AND r.message_out = m.id AND m.user = u.id 
GROUP BY d.id, u.id ORDER BY cnt DESC LIMIT 10


