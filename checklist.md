# Pentest Workflow Template

[TOC]

## Workflow

#### Pre-Login

##### Server scans
- [ ] nmap
    - `sudo nmap -v -Pn -sV --reason --version-all --top-ports 1000 $URL`
    - `sudo nmap -v -Pn -p xx,xx,xx http-apache-negotiation,http-apache-server-status,http-aspnet-debug,http-auth,http-auth-finder,http-config-backup,http-cors,http-cross-domain-policy,http-default-accounts,http-enum,http-errors,http-generator,http-iis-short-name-brute,http-iis-webdav-vuln,http-internal-ip-disclosure,http-jsonp-detection,http-mcmp,http-method-tamper,http-methods,http-ntlm-info,http-open-proxy,http-open-redirect,http-passwd,http-php-version,http-phpself-xss,http-trace,http-traceroute,http-vuln-cve2012-1823,http-vuln-cve2015-1635,http-vuln-cve2017-5638 $URL`
- [ ] nikto
	- `nikto -h $URL [-ssl] -maxtime 15m -Display 1234`
    - `nikto -config $CONFIGFILE`
- [ ] whatweb
	- `whatweb $URL --aggression=3 --cookie 'name=value' --verbose`
- [ ] gobuster
	- `gobuster -u $URL -w /usr/share/seclists/Discovery/Web-Content/big.txt -s '200,204,301,302,307,403,500' -e`
- [ ] [photon](https://github.com/s0md3v/Photon/wiki)
	- `python photon.py -u $URL --verbose --threads X --level X --cookies 'COOKIE=asd123'`
- [ ] [dirsearch](https://github.com/maurosoria/dirsearch)
	- `python3 dirsearch -u $URL --recursive --threads=X --exclude-status=CODES --cookie=COOKIE --extensions=EXTENSIONS`
- [ ] [dirhunt](http://docs.nekmo.org/dirhunt/usage.html)
	- `Tweak as needed: dirhunt $URL -e $EXT,$EXT -i html,300-500 --threads X`
- [ ] Look for admin pages with [cangibrina](https://github.com/fnk0c/cangibrina)
	- `python cangibrina.py -u $URL -v --nmap`
- [ ] [snallygaster](https://github.com/hannob/snallygaster)
	- `snallygaster -d $URL`
- TODO: wfuzz?

##### SSL/TLS checks
- [ ] Lacking TLS altogether
- [ ] sslscan $PRODURL
- [ ] sslscan $DEVURL
- [ ] Old TLS versions supported
- [ ] DES/old ciphers
- [ ] Expired/mismatched certificate
- [ ] Lack of PFS support

##### Pre-auth headers
- [ ] Check 404 page for proper headers, esp. CSP
- [ ] X-XSS-Protection
- [ ] Strict-Transport-Security
- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] Content-Security-Policy
	- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [ ] Cache-Control
- [ ] CORS headers
    - [ ] Add evil.com Origin header
    - [Comprehending CORS Findings](https://www.trustedsec.com/2018/04/cors-findings/)
- [ ] System information disclosed

##### Pre-auth cookies
- [ ] Secure
- [ ] HttpOnly
- [ ] Note session cookies for possible session fixation post-auth
- [ ] Check for liberal cookie domain scope (WAHH p.244,246)

##### Pre-auth Misc
- [ ] Find non-existent page/404 to check for custom error page
- [ ] Wappalyzer

#### Login
- [ ] Autocomplete="off"
- [ ] Burp compare login failures with good vs. bad usernames
- [ ] Username/password harvesting
	- If accounts are locked out, a message stating the lockout has occured is a way to enumerate usernames (WAHH p.197)
- [ ] Displayed passwords
	- Assumes passwords not hashed
- [ ] Parameters are passed in URL string
- [ ] Reflected username in username field
- [ ] Password in server response
- [ ] Secret question displayed
- [ ] Secret question returned in server response
- [ ] Secret question bypass
- [ ] Weak/short secret questions
- [ ] Check for non-hashed secret questions
- [ ] Test 2FA bypass (WAHH p.186)
- [ ] Look at "remember me" functionality
	- [ ] Predictable tokens to bypass 2FA
    - [ ] Replay other user's tokens to bypass 2FA
    - [ ] Check if "remember me" replaces username/password and thus removes authentication
    - [ ] Check for weak obfuscation/encoding/encryption of token/cookie
    - [ ] Remember multiple users and compare tokens
    - [ ] Determine if entire token is used or only parts
    	- Modify token to find parts that are used, e.g. Burp Intruder char frobber (WAHH p.212)
- [ ] Login multiple times and verify session token changes each time
- [ ] Check for SSO
	- [ ] Use EsPReSSO and/or SAML Raider extensions
- [ ] Check for credentials submitted in JSON
	- [ ] Check for NoSQL backed with `username=admin&password[$gt]=&submit=login`
- [ ] Check for bad password lockout
- [ ] Check for bad secret question lockout
- [ ] Compare good password response on locked out account with bad password response
- [ ] Fuzz login parameters (WAHH p.168)
    - [Arjun parameter fuzzer](https://github.com/s0md3v/Arjun)  
- [ ] Check that the same secret question is used for each authentication attempt to prevent attackers from "picking" a secret question to answer (WAHH p.195)
- [ ] Check that app is storing which secret question being asked on the server and not on the client (WAHH p.195)

#### Post-Login

##### Pre-navigation
- [ ] login with low-priv user
	- [ ] add to Autorize
- [ ] switch to high priv user
- [ ] nikto with cookies/credentials
	- [ ] set cookies in $HOME/nikto.conf
    - [ ] `SET-COOKIES="cookiename"=cookievalue`
- [ ] dirbuster with cookies/credentials
    - [ ] `gobuster -u $URL -w /usr/share/seclists/Discovery/Web-Content/big.txt -s '200,204,301,302,307,401,403,500' -e -c 'COOKIES=cookies'`
- [ ] Check for 200 vs. 302 response on login
    - [ ] Check `about:cache` for cached data
- [ ] Wappalyzer again

##### Post-auth headers
- [ ] Check 404 page for headers, esp. CSP
- [ ] X-XSS-Protection
- [ ] Strict-Transport-Security
- [ ] X-Content-Type-Options
- [ ] X-Frame-Options
- [ ] Content-Security-Policy
	- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [ ] Cache-Control
- [ ] CORS headers
	- [ ] Add evil.com Origin header
	- [ ] https://www.trustedsec.com/2018/04/cors-findings/response
- [ ] System info disclosed

##### Post-auth cookies
- [ ] Session fixation in session cookies (WAHH p.244)
- [ ] Check if pre- and post-auth cookies are the same
- [ ] See if bogus but validly formed token is accepted
- [ ] Secure parameter
- [ ] HttpOnly parameter
- [ ] Samesite parameter????

##### Post-auth Misc
- [ ] Check for last login notification
- [ ] Check for logout button
- [ ] Verify logout actually ends session by resending old tokens (WAHH p.242)
	- [ ] Verify cookie is not simply being unset on the client side

#### Navigation
- [ ] Browse all pages and use all functionality as admin user
- [ ] Burp Spider the site
	- [ ] *Exclude logout link, password reset link, any other necessary pages from scope to prevent logout issues*
	- [ ] *Exclude any delete item links*
- [ ] Add any cookies/credentials used for the site to Burp Scanner
- [ ] Run Burp Discover Content

##### Process site mapping results
- [ ] Run Burp -> site root -> enagagement tools -> analyze site
- [ ] Determine the site navigation type: application pages or functional paths
	- [ ] If functional paths, create path map (WAHH p.95)
    - [ ] Create functional diagram of application logic. Look for good ways to map this, e.g. OneNote, draw.io, etc.
- [ ] Find hidden debug parameter names with Intruder Cluster Bomb (WAHH p.97)
	- [ ] debug, test, source, hide
    - [ ] true, yes, on, 1
- [ ] Identify REST-style URLS
- [ ] Identify query string parameters
    - - [Arjun parameter fuzzer](https://github.com/s0md3v/Arjun)   
- [ ] Identify non-standard query string parameter formats (WAHH p.99)
- [ ] Run Param Miner extension
- [ ] Run Web Cache Deception Scanner extension
- [ ] Recursively gobuster newly-found directories

##### Burp Scan site
- [ ] Create macro for ensuring logged in session
- [ ] Add all user credentials to Burp scan config
- [ ] Use Intruder -> scan defined insertion points for targeted scanning

#### Post-navigation

##### Change password functionality
- [ ] CSRF token
- [ ] Password change delay
- [ ] Password reuse allowed
- [ ] Password complexity issues
- [ ] Verify that password change requires current password
	- [ ] Check for CSRF if password is not required
- [ ] Check for password in server response
- [ ] Check if existing password is verified before new password, enabling password guessing attacks
- [ ] Check for brute force possibility
- [ ] Try all combinations of good/bad/mismatched passwords
- [ ] Check if a username is provided (should never be), and if other usernames can be used/bruteforced (WAHH p.199)
- [ ] Check for multistage password change functionality (WAHH p.262)
	- [ ] See if token/creds are checked at first stage, but not at later stage of process

##### Forgot password functionality
- [ ] Check for brute force possibility
- [ ] Username harvesting possibility
- [ ] Determine if user can set challenge
- [ ] Examine password reset email token, if applicable

##### File upload issues
- [ ] Identify file uploads
- [ ] Test for zip file upload issues with [zip shotgun](https://github.com/jpiechowka/zip-shotgun)
- [ ] Use Upload Scanner extension
	- [ ] Upload file of 100KB+
	- [ ] Send to Upload Scanner extension
	- [ ] Add file to FlexiInjector if not a normal multipart upload
	- [ ] Tweak file extensions based on site stack
	- [ ] Enable logging
	- [ ] Enable reDownloader
		- [ ] If sleep RCE found, tweak timeout settings

##### Post-navigation Misc
- [ ] Compare site maps with low-priv user (WAHH p.268)
- [ ] Check that password change functionality exists
- [ ] Check for comments
- [ ] Run Paramalyzer extension
- [ ] Identify impersonation functionality (WAHH p.179)
	- [ ] Check if admins can be impersonated
- [ ] Check for account registration
- [ ] Check for account creation, e.g. as admin
	- [ ] Check for predictable usernames (WAHH p.182)
	- [ ] Check for predictable initial passwords (WAHH p.183)
- [ ] Spoof UA with browser extension and Burp (WAHH p.100)
- [ ] Unsafe configuration
- [ ] Create malformed requests to generate 4xx and 5xx errors
- [ ] Unauthenticated help pages
- [ ] Forced browsing/authentication bypass checks
	- [ ] Save all links from Burp scope to file
	- [ ] Loop through file, use curl through Burp: curl -sk -x http://127.0.0.1:8080 $url
	- [ ] Review results, make sure 302/auth is required
- [ ] Cross-site tracing (XST)
	- [ ] Send OPTIONS request
- [ ] Sensitive info in GET parameters
- [ ] Verify that client-side controls are replicated server side (WAHH p.117)
- [ ] Check for disabled elements and submit them as parameters
- [ ] Check for missing SRI attributes
- [ ] Look for hidden params with Param Miner extension

##### Injection issues
- [ ] SQL injection
	- [ ] Export Burp site map and run [SleuthQL](https://github.com/RhinoSecurityLabs/SleuthQL)
- [ ] OS command injection
	- [ ] Use Command Injection Attacker/SHELLING extension
- [ ] XPath Injection
- [ ] Server side request forgery
- [ ] LDAP injection
- [ ] XML injection (see MMWPT p.179)
	- [ ] look for `application/json` Content-Type header and change to `application/xml`
- [ ] Blind XML external entity processing
	- look for `application/json` Content-Type header and change to `application/xml`
    - [Playing with Content-Type – XXE on JSON Endpoints](https://blog.netspi.com/playing-content-type-xxe-json-endpoints/)
- [ ] Server-side template injection
	- [tplmap](https://github.com/epinna/tplmap)
- [ ] Client-side template injection
	- [angularjs-csti-scanner](https://github.com/tijme/angularjs-csti-scanner)
    - AngularJS injection, etc.
    - x{{1==1}}x
    - `{ { constructor.constructor(“alert(1)”)() } }

##### Session issues
- [ ] Determine the sesion token (WAHH p.208)
	- [ ] Remove possible tokens on session dependent page until actual session is found.
- [ ] Test if token is encoded
	- [ ] Determine if entire token is used or only parts
    - [ ] Modify token to find parts that are used, e.g. Burp Intruder char frobber (WAHH p.212)
- [ ] Session ID exposed in URL
- [ ] Session ID not invalidated after logout/timeout
	- [ ] Replay authenticated action after logout
- [ ] Predictable session tokens
	- [ ] Test randomness with Burp
- [ ] Expired session displays internal pages
- [ ] Concurrent sessions
- [ ] Check if session token in each browser is the same or different.
- [ ] Improper session time out configuration
- [ ] Check if any session tokens/other data is encrypted (WAHH p.232)
	- [ ] Bitflipping attacks, ECB
- [ ] Test sessions with Autorize extension

##### XSS
- [ ] Persistent XSS
- [ ] Reflected XSS
	- `"'<>();[]{}AbC`
    -  `"><img src=x onerror=alert(1);>`
    -  [Polyglot XSS payloads](https://github.com/0xsobky/HackVault/wiki/Unleashing-an-Ultimate-XSS-Polyglot)
    	- `jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`
    -  [XSS-Payloads.com](http://www.xss-payloads.com/)
    - [XSStrike](https://github.com/s0md3v/XSStrike)
- [ ] DOM-based XSS
- [ ] Minimal input filtering and/or output encoding
	- `<code> <pre> <plaintext>`
- [ ] Messages reflect manipulated input

##### CSRF
- [ ] Predictable CSRF token
	- [ ] Use Burp to check token randomness
- [ ] Transaction replay
- [ ] CSRF token passed in URL query string
- [ ] Test tokens between different users
- [ ] Test tokens between sessions
- [ ] Check for POST/GET method interchange
- [ ] Verify CSRF token is checked server-side (MMWPT p.93):
	- [ ] If currently logged in as user A then use the CSRF token of any other user B and check if the request of A is allowed via B's token. Then use this logic to bypass the CSRF protection.
	- [ ] Don't delete the anti-CSRF token parameter but put a blank inside its value and see if it works.
	- [ ] Put a random string with a similar length to that of the anti-CSRF token. Check to see if that works.
	- [ ] Check if the CSRF token is common to all users. If so, then use the token to construct an exploit.

##### Server-side Request Forgery (SSRF)
- [ ] Look for places to load/render URLs
	- [ ] Profile pics, links, etc.
	- [ ] Use links like http://localhost/favicon.ico to test for SSRF (THP p.89)
- [ ] Try to port scan localhost and local network
- [ ] Make use of private IP disclosure to map internal network

##### File upload/access issues
- [ ] LFI/RFI
	- [ ] Try PychoPATH extension
- [ ] Unrestricted file upload
- [ ] File upload destination directory not restricted
- [ ] Arbitrary file access through directory traversal
- [ ] Arbitrary file access through parameter manipulation

##### Sensitive/system information disclosure

##### ASP.net issues
- [ ] Debugging enabled
- [ ] Unencrypted ViewState
- [ ] ViewState without MAC enabled (Burp checks for this, WAHH p.127)

#### Misc. issues

##### API testing methodology
- [ ] List API endpoints
    - [ ] Get comprehensive list of endpoints
    - [ ] Use [JSParser](https://github.com/nahamsec/JSParser) on.js files to find endpoints
- [ ] Test all HTTP methods
    - [ ] Iterate through all permutations of enpdoint + HTTP methods
- [ ] Scope-based testing
    - [ ] Look for issues related to improper scope permissions checking
- [ ] Role-based testing
    - [ ] Look for issues related to improper role-based permissions checking
- [ ] IDOR testing


### Burp Extensions
#### Burp Store
* .NET Beautifier
* ActiveScan++
* Additional Scanner Checks
* Autorize
* Backslash Powered Scanner
* CMS Scanner
* Collaborator Everywhere
* Command Injection Attacker (SHELLING)
* CSP Auditor (Check for issue changing HTTP method)
* CSRF Scanner (Check for issue changing HTTP method)
* Decoder Improved
* Error Message Checks
* EsPReSSO
* Flow
* Freddy, Deserialization Bug Finder
* Hackvertor
* Headers Analyzer
* Heartbleed
* HTML5 Auditor
* Identity Crisis
* J2EEScan
* Java Deserialization Scanner
* Java Serial Killer
* JSON Beautifer
* JSON Web Tokens
* Param Miner
* Paramalyzer
* ParrotNG
* PsychoPATH
* Python Scripter
* Reflected Parameters
* Response Clusterer
* Retire.js
* SAML Raider
* Scan Check Builder
* Scan manual insertion point
* Session Auth
* Site Map Fetcher
* Software Vulnerability Scanner
* SSL Scanner
* Upload Scanner

#### Downloaded
* [Wildcard](https://github.com/hvqzao/burp-wildcard)
* [Cookie Decrypter](https://github.com/bellma101/cookie-decrypter)
* [SRI Check](https://github.com/bellma101/sri-check)
* [tplmap](https://github.com/epinna/tplmap/blob/master/burp_extension/README.md)
