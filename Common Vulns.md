


## Check javascript files for internal packages (like Node.js packages).
Internal packages are created and referenced only within an organization's environment. In such cases the package manager (like npm) must only query internal package registries for updates for such packages. If the package manager is querying public registeries, then this could lead to **dependency confusion**, and could pull code from a public (untrusted) registry rather than from pulling from the internal trusted regsitry. An attacker can publish a malicious package to the unclaimed public registry under the same package name as the internal package and could have the application run malicious code.


## Server-Side Template Injection (SSTI)




