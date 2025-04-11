


## Check javascript files for internal packages (like Node.js packages).
Internal JS packages are created and referenced only within an organization's environment. In such cases, the deployment server should use package manager (like npm) to only query internal package registries for updates of such packages. If the package manager is querying public registeries, then this could lead to **dependency confusion**, and could pull code from a public (untrusted) registry rather than from pulling from the internal trusted regsitry. An attacker can publish a malicious package to the unclaimed public registry under the same package name as the internal package and could have the application run malicious code.


## PHP Object Injection
The [vulnerability](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection) occurs when user-supplied input is not properly sanitized before being passed to the unserialize() PHP function. In order to successfully exploit a PHP Object Injection vulnerability two conditions must be met:

1. The application must have a class which implements a PHP magic method (such as __wakeup or __destruct) that can be used to carry out malicious attacks, or to start a “POP chain”.
2. All of the classes used during the attack must be declared when the vulnerable unserialize() is being called, otherwise object autoloading must be supported for such classes.


## Server-Side Template Injection (SSTI)




