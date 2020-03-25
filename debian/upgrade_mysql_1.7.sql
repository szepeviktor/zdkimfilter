ALTER TABLE domain CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE message_in CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE message_out CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE msg_out_ref CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE msg_ref CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
ALTER TABLE user CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

ALTER TABLE message_in ADD COLUMN spamtrap TINYINT NOT NULL DEFAULT 0 AFTER mailing_list;
ALTER TABLE domain ADD COLUMN spamtrap INT UNSIGNED NOT NULL DEFAULT 0 AFTER sent;

ALTER TABLE msg_ref ADD COLUMN dkim_selector VARCHAR(63) NOT NULL DEFAULT '' AFTER vbr;

# bounces after sending aggregate reports
DROP TABLE IF EXISTS dmarc_bounce;
CREATE TABLE dmarc_bounce (
  addr VARBINARY(320) NOT NULL PRIMARY KEY,
  since TIMESTAMP NOT NULL DEFAULT NOW() COMMENT 'bounce date',
  days INT UNSIGNED NOT NULL DEFAULT 40 COMMENT 'quarantine period'
)
engine = MyISAM
CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

delimiter //

# Called by db_sql_select_domain:
# Insert/update domain, return domain_ref
#
DROP PROCEDURE IF EXISTS recv_from_domain//

CREATE PROCEDURE recv_from_domain (
  IN m_domain VARCHAR(63),
  IN m_dkim TINYINT,
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
  IF d_white < 1 AND m_dkim = 1 THEN
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
  SELECT d_id AS domain_ref;
END //

delimiter ;


