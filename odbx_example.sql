# zdkimfilter database example using MySQL
#
# run: mysql -u zfilter < odbx_example.sql
#
# some privileges for user zfilter have to be set, for example:
# 
# CREATE DATABASE IF NOT EXISTS test_zfilter;
#
# (DROP, CREATE, ALTER ROUTINE, and CREATE ROUTINE are needed for this sql script only.)
# GRANT SELECT, INSERT, UPDATE, EXECUTE, DELETE, DROP, CREATE, ALTER ROUTINE, CREATE ROUTINE ON test_zfilter.* TO 'zfilter'@'localhost'

USE test_zfilter;

# domains that we exchange mail with
#
DROP TABLE IF EXISTS domain;
CREATE TABLE domain (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  domain VARCHAR(63) NOT NULL,
  dmarc_rua VARCHAR(64) NOT NULL DEFAULT '',
  dmarc_rec VARCHAR(63) NOT NULL DEFAULT '',
  recv INT UNSIGNED NOT NULL DEFAULT 0,
  sent INT UNSIGNED NOT NULL DEFAULT 0,
  dmarc_ri MEDIUMINT UNSIGNED NOT NULL DEFAULT 0,
  original_ri MEDIUMINT UNSIGNED NOT NULL DEFAULT 0,
  whitelisted TINYINT NOT NULL DEFAULT 0,
  add_dmarc TINYINT NOT NULL DEFAULT 0,
  add_adsp TINYINT NOT NULL DEFAULT 0,
  prefix_len TINYINT NOT NULL DEFAULT 0,
  since TIMESTAMP NOT NULL DEFAULT NOW(),
  last_report INT UNSIGNED NOT NULL DEFAULT 0,
  last_recv INT UNSIGNED NOT NULL DEFAULT 0,
  last_sent INT UNSIGNED NOT NULL DEFAULT 0,
  UNIQUE INDEX by_dom(domain)
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

# many-to-many link between domains and received messages
#
DROP TABLE IF EXISTS msg_ref;
CREATE TABLE msg_ref (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  message_in INT UNSIGNED NOT NULL COMMENT 'Foreign key to message_in',
  domain INT UNSIGNED NOT NULL COMMENT 'Foreign key to domain',
  reputation INT NOT NULL,
  auth SET ('author', 'spf_helo', 'spf', 'dkim', 'org', 'dmarc', 'aligned', 'vbr', 'rep', 'rep_s', 'dnswl', 'nx') NOT NULL,
  spf ENUM ('none', 'neutral', 'pass', 'fail', 'softfail', 'temperror', 'permerror') NOT NULL,
  dkim ENUM ('none', 'pass', 'fail', 'policy', 'neutral', 'temperror', 'permerror') NOT NULL,
  dkim_order TINYINT UNSIGNED NOT NULL DEFAULT 0,
  vbr ENUM ('spamhaus', 'who_else') NOT NULL,
  INDEX by_dom_msg(domain, message_in),
  INDEX by_msg_auth(message_in, auth)
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

# received messages
#
DROP TABLE IF EXISTS message_in;
CREATE TABLE message_in (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ino INT UNSIGNED NOT NULL,
  mtime INT UNSIGNED NOT NULL,
  pid  INT UNSIGNED NOT NULL,
  ip BINARY(4) NOT NULL COMMENT 'Ok for IPv4.  For IPv6 use VARBINARY(16)',
  date VARCHAR(63),
  message_id VARCHAR(63),
  dmarc_dkim ENUM ('none', 'fail', 'pass') DEFAULT 'none',
  dmarc_spf ENUM ('none', 'fail', 'pass') DEFAULT 'none',
  dmarc_reason ENUM ('none', 'forwarded', 'sampled_out',
    'trusted_forwarder', 'mailing_list', 'local_policy', 'other') NOT NULL DEFAULT 'none',
  dmarc_dispo ENUM ('none', 'quarantine', 'reject') NOT NULL DEFAULT 'none',
  envelope_sender VARCHAR(63) NOT NULL DEFAULT '',
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

# user table
#
DROP TABLE IF EXISTS user;
CREATE TABLE user (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  addr VARCHAR(63) NOT NULL,
  INDEX by_addr(addr(16))
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

# sent messages
#
DROP TABLE IF EXISTS message_out;
CREATE TABLE message_out (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ino INT UNSIGNED NOT NULL,
  mtime INT UNSIGNED NOT NULL,
  pid  INT UNSIGNED NOT NULL,
  user INT UNSIGNED NOT NULL COMMENT 'Foreign key to user',
  ip BINARY(4) NOT NULL COMMENT 'Ok for IPv4.  For IPv6 use VARBINARY(16)',
  rcpt_count INT UNSIGNED NOT NULL DEFAULT 1,
  date VARCHAR(63),
  message_id VARCHAR(63),
  envelope_sender VARCHAR(63) NOT NULL DEFAULT '',
  content_type VARCHAR(63) NOT NULL DEFAULT 'text/plain',
  content_encoding VARCHAR(63) NOT NULL DEFAULT '7bit',
  UNIQUE KEY (mtime, pid, ino)
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;

# many-to-many link between domains and sent messages
#
DROP TABLE IF EXISTS msg_out_ref;
CREATE TABLE msg_out_ref (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  message_out INT UNSIGNED NOT NULL COMMENT 'Foreign key to message_out',
  domain INT UNSIGNED NOT NULL COMMENT 'Foreign key to domain',
  INDEX by_dom_msg_out(domain, message_out)
)
ENGINE = MyISAM
CHARACTER SET ascii COLLATE ascii_general_ci;


delimiter //

# Called by db_sql_insert_msg_ref:
# Insert/update domain, insert msg_ref
#
DROP PROCEDURE IF EXISTS recv_from_domain//

CREATE PROCEDURE recv_from_domain (
	IN m_mi INT UNSIGNED,
	IN m_domain VARCHAR(63),
	IN m_auth SET ('author', 'spf_helo', 'spf', 'dkim', 'org', 'dmarc', 'aligned', 'vbr', 'rep', 'rep_s', 'dnswl', 'nx'),
	IN m_dkim ENUM ('none', 'pass', 'fail', 'policy', 'neutral', 'temperror', 'permerror'),
	IN m_dkim_order TINYINT UNSIGNED,
	IN m_spf ENUM ('none', 'neutral', 'pass', 'fail', 'softfail', 'temperror', 'permerror'),
	IN m_vbr VARCHAR(63),
	IN m_rep INT,
	IN m_prefix_len TINYINT,
	IN m_dmarc_ri MEDIUMINT UNSIGNED,
	IN m_original_ri MEDIUMINT UNSIGNED,
	IN m_dmarc_rec VARCHAR(63),
	IN m_dmarc_rua VARCHAR(64))
	MODIFIES SQL DATA
BEGIN
	DECLARE d_id INT UNSIGNED;
	DECLARE d_white TINYINT;
	BEGIN
		DECLARE Empty_set CONDITION FOR 1329;
		DECLARE CONTINUE HANDLER FOR Empty_set
			BEGIN
				# meanwhile, domain might have been inserted by another child
				DECLARE Duplicate_entry CONDITION FOR 1062;
				DECLARE CONTINUE HANDLER FOR Duplicate_entry
					SELECT id, whitelisted INTO d_id, d_white
						FROM domain WHERE domain = m_domain;
				SET d_white = 0;
				SET d_id = 0;
				INSERT INTO domain SET domain = m_domain;
				IF d_id = 0 THEN
					SELECT LAST_INSERT_ID() INTO d_id;
				END IF;
			END;
			SELECT id, whitelisted INTO d_id, d_white
				FROM domain WHERE domain = m_domain;
	END;
	IF d_white < 1 AND m_dkim = 'pass' THEN
		# whitelisted=1 just affects the order of signature validation attempts
		UPDATE domain SET whitelisted = GREATEST(1, whitelisted),
			prefix_len = IFNULL(m_prefix_len, prefix_len),
			recv = recv + 1, last_recv = UNIX_TIMESTAMP()+0 WHERE id = d_id;
	ELSE
		UPDATE domain SET recv = recv + 1,
			prefix_len = IFNULL(m_prefix_len, prefix_len),
			last_recv = UNIX_TIMESTAMP()+0 WHERE id = d_id;
	END IF;
	IF m_dmarc_ri > 0 THEN
		UPDATE domain SET dmarc_ri = m_dmarc_ri, original_ri = m_original_ri,
			dmarc_rec = m_dmarc_rec, dmarc_rua = m_dmarc_rua  WHERE id = d_id;
	END IF;
	INSERT INTO msg_ref SET message_in = m_mi,
		domain = d_id,
		auth = m_auth,
		dkim = m_dkim,
		dkim_order = m_dkim_order,
		spf = m_spf,
		reputation = m_rep,
		vbr = IF(STRCMP(m_vbr, 'dwl.spamhaus.org') = 0, '(spamhaus)', '()');
END //


# Called by db_sql_select_user:
# Insert/update user, insert message_out'
#
DROP PROCEDURE IF EXISTS sent_message //
CREATE PROCEDURE sent_message (
	IN m_addr VARCHAR(63),
	IN m_ino INT UNSIGNED,
	IN m_mtime INT UNSIGNED,
	IN m_pid INT UNSIGNED,
	IN m_ip BINARY(4), # for IPv6 use VARBINARY(16)
	IN m_date VARCHAR(63),
	IN m_id VARCHAR(63),
	IN m_es VARCHAR(63),
	IN m_ct VARCHAR(63),
	IN m_ce VARCHAR(63),
	IN m_rcpt INT UNSIGNED)
	MODIFIES SQL DATA
BEGIN
	DECLARE user_ref INT UNSIGNED;
	DECLARE Empty_set CONDITION FOR 1329;
	DECLARE CONTINUE HANDLER FOR Empty_set
		BEGIN
			INSERT INTO user SET addr = m_addr;
			SELECT LAST_INSERT_ID() INTO user_ref;
		END;
	SELECT id INTO user_ref FROM user WHERE addr = m_addr LIMIT 1;
	INSERT INTO message_out SET ino = m_ino,
		mtime = m_mtime,
		pid = m_pid,
		ip = m_ip,
		user = user_ref,
		date = m_date,
		message_id = m_id,
		envelope_sender = m_es,
		content_type = m_ct,
		content_encoding = m_ce,
		rcpt_count = m_rcpt;
	SELECT user_ref, LAST_INSERT_ID() AS message_ref;
END //



#	Called by db_sql_insert_target_ref:
#  Insert/update domain, insert msg_out_ref
#
DROP PROCEDURE IF EXISTS sent_to_domain //
CREATE PROCEDURE sent_to_domain (
	IN message_ref INT UNSIGNED,
	IN c_flag TINYINT UNSIGNED,
	IN m_domain VARCHAR(63))
	MODIFIES SQL DATA
BEGIN
	DECLARE d_id INT UNSIGNED;
	DECLARE d_white TINYINT;
	DECLARE Empty_set CONDITION FOR 1329;
	DECLARE CONTINUE HANDLER FOR Empty_set
		BEGIN
			INSERT INTO domain SET domain = m_domain;
			SELECT LAST_INSERT_ID() INTO d_id;
		END;
	SELECT id INTO d_id FROM domain WHERE domain = m_domain;
	IF c_flag = 0 THEN
		SET d_white = 2;
	ELSE
		SET d_white = 0;
	END IF;
	UPDATE domain SET whitelisted = GREATEST(whitelisted, d_white),
		sent = sent + 1,
		last_sent = UNIX_TIMESTAMP()+0 WHERE id = d_id;
	INSERT INTO msg_out_ref SET message_out = message_ref,
		domain = d_id;
END //

delimiter ;

# example query, to see who signed what messages:
SELECT INET_NTOA(CONV(HEX(m.ip),16,10)), m.date, FROM_UNIXTIME(m.mtime), d.domain, r.auth
FROM msg_ref AS r, message_in AS m, domain AS d
WHERE r.domain=d.id AND r.message_in=m.id AND FIND_IN_SET('dkim', r.auth);


# how many new domains have been added today?
SELECT COUNT(*) FROM domain WHERE since > (NOW() - INTERVAL 1 DAY);

# how many messages did each of them send?
SELECT d.id, d.domain, r.auth, COUNT(*) AS cnt
FROM domain AS d, msg_ref AS r, message_in AS m
WHERE d.id = r.domain AND r.message_in = m.id AND (d.since > NOW() - INTERVAL 1 DAY)
GROUP BY d.id, r.auth ORDER BY cnt DESC LIMIT 10;

# how many messages did they send as a whole?
SELECT count(*)
FROM domain AS d, msg_ref AS r, message_in AS m
WHERE d.id = r.domain AND r.message_in = m.id AND (d.since > NOW() - INTERVAL 1 DAY);


# find how many domains are stored for each authentication method
SELECT COUNT(*) as cnt, auth FROM msg_ref GROUP BY auth ORDER BY cnt DESC;

# find what messages authenticated by a given domain have been received recently
SELECT CONCAT_WS('.', LPAD(HEX(m.ino), 16, '0'), LPAD(HEX(m.mtime), 16, '0'), LPAD(HEX(m.pid), 8, '0')) AS id,
 m.date AS date, FROM_UNIXTIME(m.mtime) AS time, INET_NTOA(CONV(HEX(m.ip),16,10)) AS ip
FROM domain AS d, msg_ref AS r, message_in AS m
WHERE d.id = r.domain AND r.message_in = m.id AND d.domain='mailtrust.com'
ORDER BY m.mtime DESC  LIMIT 4;


# delete incoming messages older than 1 month
DELETE r, m FROM msg_ref AS r, message_in AS m
WHERE r.message_in = m.id AND m.mtime < UNIX_TIMESTAMP(NOW() - INTERVAL 1 MONTH);

# find domains having been orphaned that way
SELECT l.* FROM domain AS l LEFT JOIN msg_ref AS r ON r.domain = l.id
WHERE r.domain IS NULL AND l.recv > 0;


# delete outgoing messages older than 1 month
DELETE r, m FROM msg_out_ref AS r, message_out AS m
WHERE r.message_out = m.id AND m.mtime < UNIX_TIMESTAMP(NOW() - INTERVAL 1 MONTH);

# find domains having been orphaned that way
SELECT l.* FROM domain AS l LEFT JOIN msg_out_ref AS r ON r.domain = l.id
WHERE r.domain IS NULL AND l.sent > 0;


# find the messages sent in the last 24 hours (add AND u.addr = 'user@example.com')
SELECT FROM_UNIXTIME(m.mtime) AS time, u.addr FROM message_out AS m, user AS u
WHERE m.user = u.id AND m.mtime > UNIX_TIMESTAMP(NOW() - INTERVAL 1 DAY);

# find which users sent how many messages to a given list of domains
SELECT d.domain, COUNT(*) AS cnt, u.addr
FROM domain AS d, msg_out_ref AS r, message_out AS m, user AS u
WHERE d.id = r.domain AND r.message_out = m.id AND m.user = u.id AND
d.id IN (1,2,3,4,5) GROUP BY u.id;

SELECT d.domain, COUNT(*) AS cnt, u.addr
FROM domain AS d, msg_out_ref AS r, message_out AS m, user AS u
WHERE d.id = r.domain AND r.message_out = m.id AND m.user = u.id 
GROUP BY d.id, u.id ORDER BY cnt DESC LIMIT 10;

# find what messages were received from a given IP/domain in a given period
SELECT INET_NTOA(CONV(HEX(m.ip),16,10)) AS ip, FROM_UNIXTIME(m.mtime) AS time,
r.auth, r.spf, r.dkim, d.domain FROM domain AS d, msg_ref AS r, message_in AS m
WHERE r.domain = d.id AND r.message_in = m.id AND
 m.mtime >= 1429660800 AND m.mtime <= 1429747200 AND d.domain = 'yahoo.it';
