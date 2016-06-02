<?php
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

include_once 'db.php';

dbLogin();

// AJAX responder, Check if device has a valid session cookie or not
// If Yes, print 1
// If No, print 0
if(isset($_COOKIE['HOBA'])){
  dump("HOBA: login_status Got cookie for " . $_COOKIE['HOBA']);
  
  $dev = dbGetDeviceByCookie($_COOKIE['HOBA']);
  if($dev){
    print "1";
  }else{
    dump("HOBA: login_status No session found");
    print "0";
  }
}else{
  print "0";
}

dbLogout();
?>

