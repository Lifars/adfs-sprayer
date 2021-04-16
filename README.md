# adfs-sprayer

**BEWARE OF USER LOCKOUTS!!! USE AT OWN RISK!**

This script can be used either to enumerate valid usernames (checking tool's log for response time inconsistencies) or password spraying against ADFS. Useful for both blue team (check spraying is detected & blocked) and red team.

### Real-world observations

 * If user account is disabled then enumeration might work but you won't be able to guess password! (cannot verify valid credentials via ADFS)
 * If user is locked out (likely soft locked out too) then you won't be able to guess password! (cannot verify valid credentials via ADFS)
 * During username enumeration, default user accounts such as administrator, defaultaccount, krbtgt may not always look like valid usernames based on response time. Still, they're there just giving response times that doesn't make sense

## Username enumeration

This tool can be used for username enumeration too (run with `-c 1`), just spray single password with many users and look at logs. There's time difference in responses when trying valid and invalid username. If everything is setup in the usual way, following rules should apply:

 * `invalid_domain\invalid_user` = inconsistent times, e.g. first request takes 7s and all subsequent 0.2s, 0.3s,... In this case you should re-verify later to see if there was invalid domain cached or not. Sometimes you forget that you tested `invalid_domain` and run this test and get consistent times because first inconsistent value is not measured 
 * `valid_domain\invalid_user` = roughly consistent times, spikes are network errors, e.g. 4s, 5s, 4.3s or 0.2s, 0.3s, 0.21s or very short unrealistic times like 0.045, 0.025, 0.063...
 * `valid_domain\valid_user` = consistent times, spikes are network errors, response average is different from `valid_domain\invalid_user`, the difference may be only ~0.2s or several seconds 

Sidenote: UPN usernames work the same way.
Reference: [Report](https://github.com/binary1985/VulnerabilityDisclosure/blob/master/ADFS-Timing-Attack) by Joshua Platz

## Install

```
pip3 install requests urllib3
git clone https://github.com/Lifars/adfs-sprayer
```

## Run
```
python3 adfs-sprayer.py -h
usage: adfs-sprayer.py [-h] -u USER_LIST -D AD_DOMAIN -a ADFS_URL [-p PASSWORD] [-pf PWFILE] [-pd PF_DELAY] [-t TIMEOUT] [-d DELAY] [-i PID] [-l] [-c THREAD_CNT] [-g]

Spray passwords or enumerate usernames on ADFS

optional arguments:
  -h, --help            show this help message and exit
  -u USER_LIST, --user-list USER_LIST
                        Username list path
  -D AD_DOMAIN, --ad-domain AD_DOMAIN
                        AD domain used to add before/after usernames. Example: CONTOSO will make username CONTOSO\user1, contoso.local will make username user1@contoso.local
  -a ADFS_URL, --adfs-url ADFS_URL
                        URL to ADFS, e.g. https://sts.contoso.com/
  -p PASSWORD, --password PASSWORD
                        Password
  -pf PWFILE, --password-file PWFILE
                        Password file
  -pd PF_DELAY, --password-file-delay PF_DELAY
                        Guaranteed delay in seconds between starting to spray another password in Password file
  -t TIMEOUT, --timeout TIMEOUT
                        Timeout in seconds for each sent request
  -d DELAY, --delay DELAY
                        Delay in seconds between each sent request
  -i PID, --party-id PID
                        ADFS Party ID. If not present, the tool will login directly into ADFS and not attempt to login to one of relay parties
  -l, --http-log        Log all HTTP request-response to file
  -c THREAD_CNT, --concurrency THREAD_CNT
                        Number of threads to use
  -g, --guarantee-password-delay
                        Ensure Password file delay value is met for all users
```

## Similar tools in no particular order

 * [adfs-spray.py](https://github.com/Mr-Un1k0d3r/RedTeamScripts/blob/master/adfs-spray.py) by Mr-Un1k0d3r
 * [ADFSpray](https://github.com/xFreed0m/ADFSpray) by xFreed0m
 * [o365spray](https://github.com/0xZDH/o365spray) by 0xZDH
