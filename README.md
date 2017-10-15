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
$sUrl = "https://mywebsite.com/?var='%22><script>alert();</script>";

# Load with construct param
$oXss = new XssUrl($sUrl);

# Or use setUrl on an alredy loaded instance
$oXss = new XssUrl;
$oXss->setUrl($sUrl);

# Detect
if($oXss->isXss()) { die; }

```