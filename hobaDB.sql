/*
  The file is part of the HOBA server.
  
  HOBA server is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  HOBA server is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.
  Copyright (C) 2016, Andrew McConachie, <andrew@depht.com>
*/

CREATE TABLE `users` (
  `uid` int(11) NOT NULL AUTO_INCREMENT,
  `uName` text,
  `pw` varchar(255),
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
  `did` int(11) NOT NULL,
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

CREATE TABLE `firstNames` (
  `nid` int(11) NOT NULL AUTO_INCREMENT,
  `firstName` text NOT NULL,
  UNIQUE KEY `nid` (`nid`)
);

CREATE TABLE `messages` (
  `mid` int(11) NOT NULL AUTO_INCREMENT,
  `uid` int(11) NOT NULL,
  `message` text NOT NULL,
  UNIQUE KEY `mid` (`mid`)
);

CREATE TABLE `bondMap` (
  `bid` int(11) NOT NULL AUTO_INCREMENT,
  `srcDid` int(11) NOT NULL,
  `trgUid` int(11) NOT NULL,
  UNIQUE KEY `bid` (`bid`)
);

