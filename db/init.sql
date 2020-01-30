-- noinspection SqlNoDataSourceInspectionForFile

INSERT INTO users (login, password, ip, mac) VALUES ('vasya', '12345', '10.0.0.1', '00:00:00:00:00:01');
INSERT INTO nas (ip, secret, auth_type) VALUES ('127.0.0.1', 'secret', 0);
INSERT INTO reply_attrs(user_id, reply_code, attr_id, attr_value) VALUES
  (1, 2, 8, '10.0.0.5'),
  (1, 2, 9, '255.255.255.255'),
  (1, 2, 25, '3600');
INSERT INTO dictionary (code, type, name) VALUES
	(1, 1, "User-Name"),
	(2, 1, "User-Password"),
	(3, 1, "CHAP-Password"),
	(4, 2, "NAS-IP-Address"),
	(5, 3, "NAS-Port"),
	(6, 3, "Service-Type"),
	(7, 3, "Framed-Protocol"),
	(8, 2, "Framed-IP-Address"),
	(9, 2, "Framed-IP-Netmask"),
	(10, 3, "Framed-Routing"),
	(11, 0, "Filter-Id"),
	(12, 3, "Framed-MTU"),
	(13, 3, "Framed-Compression"),
	(14, 2, "Login-IP-Host"),
	(15, 3, "Login-Service"),
	(16, 3, "Login-TCP-Port"),
	(18, 0, "Reply-Message"),
	(19, 1, "Callback-Number"),
	(20, 1, "Callback-Id"),
	(22, 0, "Framed-Route"),
	(23, 3, "Framed-IPX-Network"),
	(24, 1, "State"),
	(25, 1, "Class"),
	(26, 1, "Vendor-Specific"),
	(27, 3, "Session-Timeout"),
	(28, 3, "Idle-Timeout"),
	(29, 3, "Termination-Action"),
	(30, 1, "Called-Station-Id"),
	(31, 1, "Calling-Station-Id"),
	(32, 1, "NAS-Identifier"),
	(33, 1, "Proxy-State"),
	(34, 1, "Login-LAT-Service"),
	(35, 1, "Login-LAT-Node"),
	(36, 1, "Login-LAT-Group"),
	(37, 3, "Framed-AppleTalk-Link"),
	(38, 3, "Framed-AppleTalk-Network"),
	(39, 1, "Framed-AppleTalk-Zone"),
	(40, 3, "Acct-Status-Type"),
	(41, 3, "Acct-Delay-Time"),
	(42, 3, "Acct-Input-Octets"),
	(43, 3, "Acct-Output-Octets"),
	(44, 1, "Acct-Session-Id"),
	(45, 3, "Acct-Authentic"),
	(46, 3, "Acct-Session-Time"),
	(47, 3, "Acct-Input-Packets"),
	(48, 3, "Acct-Output-Packets"),
	(49, 3, "Acct-Terminate-Cause"),
	(50, 1, "Acct-Multi-Session-Id"),
	(51, 3, "Acct-Link-Count"),
	(60, 1, "CHAP-Challenge"),
	(61, 3, "NAS-Port-Type"),
	(62, 3, "Port-Limit"),
	(63, 1, "Login-LAT-Port");