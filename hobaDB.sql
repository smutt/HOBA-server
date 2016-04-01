CREATE TABLE `users` (
  `uid` int(11) NOT NULL AUTO_INCREMENT,
  `userNames` text,
  UNIQUE KEY `uid` (`uid`)
);

CREATE TABLE `devices` (
  `did` int(11) NOT NULL AUTO_INCREMENT,
  `uid` int(11) NOT NULL,
  `dName` text,
  UNIQUE KEY `did` (`did`)
);

CREATE TABLE `pubKeys` (
  `pid` int(11) NOT NULL AUTO_INCREMENT,
  `uid` int(11) NOT NULL,
  `kid` varchar(512) NOT NULL,
  `pubKey` text NOT NULL,
  UNIQUE KEY `pid` (`pid`)
);

CREATE TABLE `sessions` (
  `sid` int(11) NOT NULL AUTO_INCREMENT,
  `did` int(11) NOT NULL,
  `cookie` text NOT NULL,
  `tStamp` int unsigned NOT NULL,
  UNIQUE KEY `sid` (`sid`)
);

CREATE TABLE `challenges` (
  `cid` int(11) NOT NULL AUTO_INCREMENT,
  `challenge` text NOT NULL,
  `tStamp` int unsigned NOT NULL,
  UNIQUE KEY `cid` (`cid`)
);
