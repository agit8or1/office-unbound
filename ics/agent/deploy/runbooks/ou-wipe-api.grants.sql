-- Grants for the ou-wipe-api DB account (run once as DB root on the groupware node). Security review 4, L9: the policy ACK of a NEW device
-- (INSERT INTO user_devices) needs INSERT, which the first version of this account lacked.
CREATE USER IF NOT EXISTS 'ou_wipe'@'localhost' IDENTIFIED BY '<from /etc/ou-rb/wipe-api.json>';
GRANT SELECT (id, username) ON email.users TO 'ou_wipe'@'localhost';
GRANT SELECT, INSERT, UPDATE ON email.user_devices TO 'ou_wipe'@'localhost';
GRANT SELECT, INSERT ON email.user_device_history TO 'ou_wipe'@'localhost';
FLUSH PRIVILEGES;
