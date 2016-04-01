<?php
include_once 'db.php';
include_once 'challenge.php';
dbLogin();

// Test for cookie
if(isset($_COOKIE['HOBA'])){
  $cookie = $_COOKIE['HOBA'];
  // Retrieve cookie value from DB
}else{
  $chal = getChal(getPeer());
  dbAddChal($chal);
  
  header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $chalTimeout);
  header('HTTP/1.0 401 Unauthorized');

print <<< EOF
<html>
<head>
  <meta http-equiv="refresh" content="1;URL=index.php"/>
  <title>
    Redirecting...
  </title>
</head>
<body>
  If you are not redirected please click <a href="index.php">here</a>.
</body>
</html>
EOF;
}
dbLogout();
?>