Coercive Security Xss
=====================

A simple detection of XSS attack in url. like '<' '>' and quotes...

Get
---
```
composer require coercive/xss
```

Load
----
```php
use Coercive\Security\Xss;

# Test URL
$url = "https://mywebsite.com/?var='%22><script>alert();</script>";

# Load with construct param
$xss = new XssUrl($url);

# Or use setUrl on an alredy loaded instance
$xss = new XssUrl;
$xss->setUrl($url);

# Detect
if($xss->isXss()) { die; }

```

New detection optimisation
--------------------------
```php
# Test encoded url with script => alert('XSS')
$url = "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x0027&#x29";

# Load with construct param
$xss = new XssUrl($url);

# Show example
echo '<a href="'.$url.'">BEFORE<a>';
echo '<br />';
echo '<a href="'.$xss->getFiltered().'">AFTER<a>';
```
