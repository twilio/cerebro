Cerebro
=======
Cerebro finds secrets such as passwords, tokens, private keys and more in a Git repo.

## Tech Stack
Cerebro requires:
* Python 3.5
* SQLite

## Getting Started
### Configure Target Repositories
Populate the `targets.yaml` file in the config directory using the example:

`$ cp config/targets.example.yaml config/targets.yaml`

### Local Usage
Clone this repo and export the following environment variables:
* CEREBRO_DATABASE_URL - full/path/to/sqlite/database/file

If you wish to receive Cerebro results in Slack, also configure:
* SLACK_API_URL - Incoming web hooks endpoint from Slack
* SLACK_CHANNEL_OR_USER - The @user or #channel to send scan notifications to

Set up the environment:

`$ make local-install`

Execute (or setup a cron job for the following code snippet):

`$ python cerebro.py` 

or

`$ make local-run`

Run the tests:

`$ make local-test`

### Docker-compose Usage
Copy the env-example file & edit it appropriately:

`$ cp env-example to .env`

Build the docker environment (it will use Ubuntu-latest)

`$ make docker-build`

Run the tests:

`$ make docker-tests`

Run cerebro:

`$ make docker-run`

## Tests
Execute
```
$ pytest -sv tests/
```

## Reporting
A summary of results is provided in JSON format by default or can be provided via Slack, while detailed results can be reviewed directly in SQLite or
[Todo - Add the url of the *cerebro* dashboard once we have a box configured for it]. Alternatively, results can be viewed directly in SQLite.

## Definitions
These definitions describe how raw data is processed and stored:
* BLOCK_SIZE - this is the size for any contiguous set of characters (i.e. BASE64 or HEXADECIMAL) searched for in the
codebase entropy. Default is 20
* TOKENS - a BLOCK_SIZE of characters that were matched during the scan process
* BLOBS - represents portions of a file containing a TOKEN

## Design Notes
There are 3 high-level components involved in the operation of *cerebro*, they are:
* Git Level Operations
    * Pulling the latest commit of the ```master``` branch from each repo in ```targets.yaml```, checking for
    diffs in repo if repo had been previously scanned (i.e. pulled) and creating sub-directories with "diffed" content
    (i.e. stored in ```workspace/diffs```) for subsequent scanning.
* Operating System Level Operations:
    * ```targets.yaml```: a list of repos for *cerebro* to scan.
    * ```bad_patterns.txt```: a list of regexes used by ```egrep```.
    * ```egrep``` : performs recursive regex grepping for each repo from ```targets.yaml``` using patterns from
    ```bad_patterns.txt```.
* Python Level Operations:
    * Each matched string is tested for entropy
    using [Shannon's algorithm](http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html),
    the basic concept of which is - a BLOCK_SIZE of BASE64 characters with an entropy greater than 4.5 or BLOCK_SIZE
    of HEXADECIMAL characters with entropy greater than 3.0 is flagged as a TOKEN.
    * For config files however (i.e. .conf, .yaml, .ini, .erb, .rb), we set the BLOCK_SIZE to 6, which ensures that
    smaller chunks of tokens with sufficient entropy are matched
    * These results are then further filtered by options set in the ```main.yaml``` configuration file e.g. excluding test or 3rd-party library framework directories and or specific files from the search.
