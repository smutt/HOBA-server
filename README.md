# HOBA-server
Experiments with server side development of HTTP Origin Based Authentication (RFC 7486)

Licensed under GPLv3

This has been developed/tested with Apache2.4 on OpenBSD and FreeBSD

### Some Apache2.4 config that might help you get started
The directory foo/hoba-ssl/.well-known/hoba contains symbolic links to the actual PHP scripts in foo/hoba-ssl/

```
<Directory foo/hoba-ssl>
  Options FollowSymlinks
  AllowOverride all
  Order allow,deny
  Allow from all
  SetHandler php7-script 

  # Allow Authorization header to be modified
  RewriteEngine On
  RewriteCond %{HTTP:Authorization} ^(.*)
  RewriteRule .* - [e=HTTP_AUTHORIZATION:%1]
</Directory>

<Directory foo/hoba-ssl/.well-known/hoba>
  Options FollowSymLinks
  SetHandler php7-script 
</Directory>
```

### Test Website
There is a test website up and running to play with this @ https://hoba.name/

