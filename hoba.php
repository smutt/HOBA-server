<?php 

/* 
 *
 * Copyright (C) 2013, Tolerant Networks Limited, Stephen Farrell, <stephen@tolerantnetworks.com>
 * Copyright (C) 2015, Andrew McCoanchie, andrew.mcconachie@icann.org
 *
 * Original code by Stephen Farrell, then modified by Andrew McConachie.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 *
 */

/*
  Server side implementation of HOBA RFC 7486

  -apache needs rewrite on (rewrite.load to be in mods-enabled)
  -then add this to the site config:
    RewriteEngine On
    RewriteCond %{HTTP:Authorization} ^(.*)
    RewriteRule .* - [e=HTTP_AUTHORIZATION:%1]
*/

include_once 'challenge.php';
include_once 'hoba_auth.php';

session_start();

if (isset($_SESSION['inited'])) {
	$foo=$_SESSION['counter'];
	$_SESSION['counter']=$foo+1;
} else {
	$_SESSION['inited']=true;
	$_SESSION['counter']=0;
}

if (isset($_SESSION['HOBAState'])) {
	if ($_SESSION['HOBAState']=="Loggedin") {
		header("HTTP/1.0 200 gotcha");
		echo "<html><head/><body><p>You're in!</p></body></html>";
		return;
	}
} 

if (isset($_SERVER['HTTP_HOBA']) || isset($_SERVER['HTTP_AUTHORIZATION'])) {
	
	// the rewrite rule sets this always
	$hoba_res=$_SERVER['HTTP_AUTHORIZATION'];
	
	if ($hoba_res!="") {
		// debug
		$rv=hoba_check_auth();
		if ($rv==0) {
			// need $_SESSION['kid'] for later, hopefully this copies that over to new session
			session_regenerate_id(true);
			$currentCookieParams = session_get_cookie_params();  
			$sidvalue = session_id();  
			setcookie(  
				'PHPSESSID',//name  
				$sidvalue,//value  
				0,//expires at end of session  
				$currentCookieParams['path'],//path  
				$currentCookieParams['domain'],//domain  
				true, //secure  
				true // HTTP only
			);
			$crv=setcookie("HOBAState","Loggedin",0,"/","",true,false);
			$_SESSION['HOBAState']='Loggedin';
			echo "<p>That worked nicely</p>";
			return;
		} else {
			$crv=setcookie("HOBAState","Loggedout",0,"/","",true,false);
			$_SESSION['HOBAState']='Loggedout';
			header("HTTP/1.0 403 Unauthorized");
			echo "<p>Bummer something went wrong</p>";
			echo "<pre>";
			foreach (getallheaders() as $name => $value) {
				echo "$name: $value\n";
			}
			echo '</pre></body></html>';
			return;
		}
	}
} 

if (1) { // challenge 'em
	$from=getPeer();
	$challenge=getChal($from);
	header('WWW-Authenticate: HOBA: challenge='.$challenge.",expires=200");
	header('HTTP/1.0 401 Unauthorized'); 
	// cheat to save a RTT, putting same challenge in body - means JS on client can see it
	//echo('<div id="HOBA-challenge">challenge='.$challenge.',expires=200></div>');

	print <<<HEADERSTUFF

<!DOCTYPE html>
<html>
<head>
<title>HOBA Login</title>
<meta name="ROBOTS" content="NOINDEX, NOFOLLOW">
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<meta http-equiv="content-type" content="application/xhtml+xml; charset=UTF-8">
<meta http-equiv="content-style-type" content="text/css">
<body>
<center>
<h1>HOBA HTTP 401 Based Login</h1>
<div style="width:10%" id="middle">
<div id="login-state">
<img src="/redx-small.png" width="20%" />
</div>
<input id="login-button" type="button" value="Login" 
		class="btn" onmouseover="hov(this,'btn btnhov')" 
		onmouseout="hov(this,'btn')" 
		onClick="hoba_ha_login();"/> 

<input id="logout-button" type="button" value="Logout" 
	class="btn" onmouseover="hov(this,'btn btnhov')" 
	onmouseout="hov(this,'btn')" 
	onClick="hoba_ha_logout();" /> 

</div>
</head>
<body>

HEADERSTUFF;


	// cheat to save a RTT, putting same challenge in body - means JS on client can see it
	// also cheating by telling client what HTTP method is used (can't find how JS can
	// detect that;-)
	echo '<div id="HOBA-challenge">challenge='.
			$challenge.
			',expires=200,method='.
			$_SERVER['REQUEST_METHOD'].
			'</div><div id="sesscnt">'.  $_SESSION['counter'].  '</div>';

	echo "<pre>";
	foreach (getallheaders() as $name => $value) {
		echo "$name: $value\n";
	}
	echo '</pre></body></html>';
}

?>
