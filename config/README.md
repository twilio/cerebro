Regex Patterns Used
-------------------
The following patterns are used to match/search for secrets, tokens and credentials in the codebase. 

All matches are case-insensitive. While it's possible to merge many of these into one line, it'll be a lot harder to 
maintain that way, thus a line per pattern.

This patterns are consumed by `egrep`'s file option (i.e. `-f`), which reads a list of regex patterns from a file

```

password[\w]*\s*\=\s*(\'+|\"+)[a-z0-9]{30,40}}
# Used to match alphanumeric passwords containing between 30 and 40 characters.

s3[\w]*\s*\=\s*(\'+|\"+)[a-z0-9]{30,40}
# Used to match AWS S3 credentials`

secret[\w]*\s*\=\s*(\'+|\"+)[a-z0-9]{30,40}
# Used to match AWS SECRET`

credentials[\w]*\s*\=\s*(\'+|\"+)[a-z0-9]{30,40}
# Used to match AWS CREDENTIALS`

key[\w]*\s*\=\s*(\'+|\"+)[a-z0-9]{30,40}
# Used to match API or other sensitive KEYS in the codebase`

^aws[\w]*\s*\=\s*(\'+|\"+)[a-z0-9]{30,40}
# Used to match AWS credentials, which start with the word AWS

twilio\_*[\w]*\s*\=\s*(\'+|\"+)[a-z0-9]{30,40}
# Used to match TWILIO credentials`

token[\w]*\s*\=\s*(\'+|\"+)[a-z0-9]{30,40}
# Used to match TOKENs in the codebase`

private\skey[\-]{5}
# Used to match PIVATE keys in the code base

^(acqusition|apidev-coop|bzip|crypt|django-server|pwd|setup-tools|telnet|urlib3|urllib) $
# Used to match malicious Python packages published to PyPi

\s*(\'+|\"+)[a-z0-9]{30,40}
# A catch-all match for whatever seems like a password, token, hash e.t.c but isn't caught by other patterns above

```
