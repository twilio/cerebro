# -*- coding: utf-8 -*-
"""Cerebro Secret Sniffing
This tool finds secrets such as passwords, tokens, private keys and
more in a Git repositories or list of Git repositories.

Copyright (C) 2017 Twilio Inc.

Cerebro is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version. Cerebro is distributed in the
hope that it will be useful, but WITHOUT ANY WARRANTY; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with Cerebro; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
"""

import os
import subprocess
import shutil

from hashlib import sha1
from os import getcwd, chdir, popen, makedirs
from os.path import isdir
from re import compile, IGNORECASE
from sqlite3 import connect, DatabaseError
from datetime import datetime
from collections import namedtuple
from truffleHog.truffleHog import get_strings_of_set
from yaml import safe_load

from requests import post
from git import Repo
from git.exc import GitCommandError
from cerebro.cerebro_utils import shannons_entropy_batch

class Cerebro(object):
    # region Constants and Static Methods

    CEREBRO_DIR = getcwd()
    WORKSPACE_DIR = os.path.join(
        CEREBRO_DIR,
        os.environ.get("CEREBRO_WORKSPACE_DIR","workspace")
    )
    REPOS_BASE_DIR = os.path.join(
        WORKSPACE_DIR,
        "repos"
    )
    DIFF_BASE_DIR = os.path.join(
        WORKSPACE_DIR,
        "diffs"
    )
    CONFIG_BASE_DIR = os.path.join(
        CEREBRO_DIR,
        "config"
    )

    TOKEN = namedtuple('Token', 'tuuid token date_found')
    BLOB = namedtuple('Blob', 'muuid filepath row_number date_found')

    def __init__(self):
        self.DB_CONN = connect(os.environ.get('CEREBRO_DATABASE_URL', 'cerebro.db'))
        self.stored_matches = []

        self.new_token_last_logged_at = None
        self.new_blob_last_logged_at = None

        self._bad_patterns_file = '{CONFIG_BASE_DIR}/bad_patterns.txt'.format(CONFIG_BASE_DIR=Cerebro.CONFIG_BASE_DIR)


        self.config = Cerebro.yaml_loader(self.CONFIG_BASE_DIR + '/main.yaml')
        self.contents = self.config['main']
        self.scan_targets = self.contents['scan_targets']
        self.hex_chars = self.contents['general']['hex_chars']
        self.base64_chars = self.contents['general']['base64_chars']
        self.regexes_sought = self.contents['regexes_sought']
        self.regexes_ignored = self.contents['regexes_ignored']
        self.valid_hash_length = self.contents['general']['valid_hash_length']
        self.excluded_extensions = self.contents['excluded_extensions']
        self.excluded_directories = self.contents['excluded_directories']
        self.extensions_with_extra_checks = self.contents['extensions_with_extra_checks']

        with self.DB_CONN as wn_cursor:
            try:
                wn_cursor.execute('Select count(rowid) from Tokens')
            except DatabaseError:
                wn_cursor.execute(
                    """
                    CREATE TABLE Tokens(
                       tuuid varchar(150) UNIQUE not null,                      -- uuid for token
                       token text UNIQUE not null,                              -- actual token found
                       date_found datetime default current_timestamp,           -- date found
                       is_false_positive boolean default false                  -- flag for updates
                    )
                    """
                )

            try:
                wn_cursor.execute('Select count(rowid) from Blobs')
            except DatabaseError:
                wn_cursor.execute('PRAGMA foreign_keys = ON')
                wn_cursor.execute("""
                    CREATE TABLE Blobs(
                       muuid varchar(150) not null,                             -- match uuid
                       repo_name varchar(150) not null,                         -- short repo_name
                       commit_hash VARCHAR(35) not null,                        -- sha1
                       filename varchar(150) not null,                          -- local filepath of affected file
                       row_number integer not null,                             -- row
                       tuuid_fk REFERENCES tokens(tuuid) ON DELETE CASCADE,     -- FK to Tokens table
                       date_found datetime default current_timestamp,            -- date found
                       is_false_positive                                        -- flag for updates
                    );
                """)

    def get_stored_matches(self):
        return self.stored_matches

    @staticmethod
    def yaml_loader(yaml_file):
        try:
            with open(yaml_file,'r') as f:
                yaml_contents = safe_load(f)
        except IOError as err:
            print('Error loading Cerebro yaml {yaml_file}: {err}'.format(
                yaml_file=yaml_file,
                err=err))
            exit(1)
        return yaml_contents

    # endregion

    def get_latest_commit(self, local_repo_path):
        """
        Return the latest commit hash for this repo
        :param <Git Repo>local_repo_path:
        :return: string
        """
        latest_commit = None
        if isdir(local_repo_path):
            chdir(local_repo_path)
            p = subprocess.Popen(["git","log","-1","--oneline"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            (output, err) = p.communicate()
            p_status = p.wait()
            latest_commit = output.decode().split(' ')[0]

        return latest_commit

    def build_where_in_clause(self, wherein_iterable):
        wherein = ', '.join(['"{elm}"'.format(elm=elm) for elm in wherein_iterable])
        return wherein

    def mark_tokens_and_blobs_as_false_positive(self, affected_muuid_blobs):
        """
        Mark the Token and associated Blobs in affected_muuid_blobs as False +ves
        :param <list>affected_muuid_blobs:
        :return: bool|str
        """
        blobs_muuid = tuple(set(affected_muuid_blobs))

        with self.DB_CONN as wn_cursor:
            try:
                qry = "SELECT tuuid_fk from Blobs WHERE muuid IN ({})".format(self.build_where_in_clause(blobs_muuid))
                blob_tuuids_qry = wn_cursor.execute(qry).fetchall()
                blob_tuuids = list(set([str(tuuid[0]) for tuuid in blob_tuuids_qry]))

                mark_false_positive_qry = "UPDATE Tokens SET is_false_positive = 'true' WHERE tuuid IN ({})".format(
                    self.build_where_in_clause(blob_tuuids))
                wn_cursor.execute(mark_false_positive_qry)

                soft_delete_blobs_qry = "UPDATE Blobs SET is_false_positive = 'true' WHERE muuid IN ({})".format(
                    self.build_where_in_clause(blobs_muuid))
                wn_cursor.execute(soft_delete_blobs_qry)
                return True
            except Exception as e:
                return e.message

    def prepare_diff_for_scan(self, domain, repo, last_known_commit, latest_commit):
        """
        Create a new directory containing the objects found between 2 commit hashes
        :param <Git Repo>repo:
        :param <str> last_known_commit: commit hash before `git pull`
        :param <str> latest_commit: commit hash after `git pull`
        """
        commit_span = '{last_known_commit}..{latest_commit}'.format(
            last_known_commit=last_known_commit,
            latest_commit=latest_commit)
        p = subprocess.Popen(['git','diff',commit_span,'--name-only','--diff-filter=AMRC','--'],
                        stdout=subprocess.PIPE)
        (output, err) = p.communicate()
        p_status = p.wait()
        diff_objects = output.decode().strip().split('\n')

        repo_diff_dir = os.path.join(self.DIFF_BASE_DIR, domain, repo, "master")
        if isdir(repo_diff_dir):
            shutil.rmtree(repo_diff_dir, ignore_errors=True)

        makedirs(repo_diff_dir)
        for obj in diff_objects:
            p = subprocess.Popen(['cp','-R',obj,repo_diff_dir])
            (output, err) = p.communicate()
            p_status = p.wait()

    def run_scan(self, target_directory):
        """
        Perform recursive search on target_directory for un-wanted patterns
        :param <str> target_directory: path to repo to be scanned
        :return: string
        """
        chdir(Cerebro.CEREBRO_DIR)
        excluded_extensions = ",".join(self.excluded_extensions)
        excluded_directories = ",".join(self.excluded_directories)
        egrep = 'egrep {0} -d recurse --color -nbirI -f {1}'.format(target_directory, self._bad_patterns_file)
        egrep_command = egrep + " --exclude-dir={" + excluded_directories + "} --exclude=*{" + excluded_extensions + "}"
        scan_results = popen(egrep_command)
        return scan_results

    def token_has_valid_length_and_number(self, input_string):
        """
        :param <str> input_string
        :return: bool
        """
        return len(input_string) >= int(self.valid_hash_length) and compile(self.regexes_sought[1]).search(
            input_string) is not None

    def token_matches_regex_matcher(self, input_string, regex_iterable, ignore_case=True):
        """
        :param <str> input_string
        :param <list> regex_iterable: list of regexes
        :param <bool> ignore_case
        :return: bool
        """
        if ignore_case:
            regexes = [compile(rgx, IGNORECASE) for rgx in regex_iterable]
        else:
            regexes = [compile(rgx) for rgx in regex_iterable]

        matches = map(lambda x: x.search(input_string) is not None, regexes)
        return any(matches)

    def token_matches_regexes_sought(self, input_string):
        return self.token_matches_regex_matcher(input_string, self.regexes_sought)

    def token_matches_regexes_ignored(self, input_string):
        return self.token_matches_regex_matcher(input_string, self.regexes_ignored, ignore_case=False)

    def token_has_sufficient_entropy(self, input_string, char_frequency=20):
        """
        Adapted from https://github.com/dxa4481/truffleHog/blob/master/truffleHog.py
        base64_chars with entropy > 4.5 or hex_chars with entropy > 3.0 qualify as a hash
        :param <str> input_string:
        :param <int> char_frequency
        :return: bool (based on the score)
        """
        base64_string = get_strings_of_set(input_string, self.base64_chars, char_frequency)
        hex_string = get_strings_of_set(input_string, self.hex_chars, char_frequency)
        b64entropy = shannons_entropy_batch(self.base64_chars, self.hex_chars, base64_string, self.base64_chars)
        hexentropy = shannons_entropy_batch(self.base64_chars, self.hex_chars, hex_string, self.hex_chars)
        return b64entropy > 4.5 or hexentropy > 3.0

    def token_matches_base_criteria(self, input_string):
        return self.token_has_sufficient_entropy(input_string) or self.token_matches_regexes_sought(
            input_string) and not self.token_matches_regexes_ignored(input_string)

    def affected_file_is_a_config(self, local_filepath):
        if local_filepath and len(local_filepath.split('.')) > 1:
            file_extension = local_filepath.split('.')[1]
            return file_extension in self.extensions_with_extra_checks.keys(), file_extension

        return False, None

    def token_matches_config_token_criteria(self, input_string, config_threshold):
        return self.token_has_sufficient_entropy(input_string, config_threshold)

    @staticmethod
    def results_as_json(result_list):
        """
        Return JSON results of matched tokens
        :param result_list:
        :return JSON
        """
        repo_names = list(set([result_set['result_details']['repo_name'] for result_set in result_list]))
        results_by_repo = []

        for repo_name in repo_names:
            tokens_found = []

            for result_set in result_list:
                result_details = result_set['result_details']

                if result_details['repo_name'] == repo_name:
                    tokens_found.append({
                        "token": result_set['token'],
                        "affected_file": result_details['affected_file'],
                        "line_number": result_details['row_number'],
                        "commit_hash": result_details['commit_hash']
                    })

            results_by_repo.append({"repo": repo_name, "tokens_found": tokens_found})

        return {"results":results_by_repo}

    def store_results(self, result_list):
        """
        Create new Tokens and corresponding Blob entries
        :param result_list:
        """
        new_tokens_by_tuuids = []
        new_blobs_by_muuids = []
        with self.DB_CONN as wn_cursor:
            existing_tuuids_qry = wn_cursor.execute(
                """
                SELECT tuuid from Tokens
                """
            ).fetchall()
            existing_tuuids = tuple([str(id_list[0]) for id_list in existing_tuuids_qry])

            for result in result_list:
                if result['token_id'] not in existing_tuuids:
                    new_tokens_by_tuuids.append((result['token_id'], result['token'],))

            new_tokens_by_tuuids = list(set(new_tokens_by_tuuids))

            if len(new_tokens_by_tuuids) > 0:
                wn_cursor.executemany(
                    """
                    INSERT INTO Tokens(tuuid, token) VALUES (?, ?)
                    """,
                    new_tokens_by_tuuids
                )

            existing_muuids_qry = wn_cursor.execute(
                """
                SELECT muuid FROM Blobs
                """
            ).fetchall()
            existing_muuids = tuple([str(id_list[0]) for id_list in existing_muuids_qry])

            for result in result_list:
                result_details = result['result_details']
                if result_details['muuid'] not in existing_muuids:
                    blob_record = (result_details['muuid'], result_details['tuuid'], result_details['repo_name'],
                                   result_details['commit_hash'], result_details['affected_file'],
                                   result_details['row_number'],)
                    new_blobs_by_muuids.append(blob_record)

            if len(new_blobs_by_muuids) > 0:
                wn_cursor.executemany(
                    """
                    INSERT INTO Blobs(muuid, tuuid_fk, repo_name, commit_hash, filename, row_number)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    new_blobs_by_muuids
                )

    def append_new_match(self, token_id, token, **details):
        known_token_ids = set([match['token_id'] for match in self.stored_matches])
        if token_id not in known_token_ids:
            self.stored_matches.append(
                {
                    'token_id': token_id,
                    'token': token,
                    'result_details': details
                }
            )

    def process_results(self, raw_results, **kwargs):
        """
        Sanitize scan results for storage
        :param <Open FileObject> raw_results
        :param <dict> kwargs: {'repo_name': name of repo, 'commit_hash': last_known_commit}
        """
        results = raw_results.read().split('\n')
        for entry in results:
            base_criteria_is_matched = False
            if len(entry.strip()) > 0:
                parts = entry.split(':')
                affected_file = parts[0]
                row_number = parts[1]
                token_matched = parts[len(parts) - 1]

                tuuid = sha1(token_matched.encode('utf-8')).hexdigest()
                muuid = sha1('{0}{1}{2}'.format(affected_file, row_number, token_matched).encode('utf-8')).hexdigest()
                kwargs.update(
                    {"muuid": muuid, "tuuid": tuuid, "affected_file": affected_file, "row_number": row_number})

                if self.token_matches_regexes_ignored(token_matched):
                    continue

                if self.token_matches_base_criteria(token_matched):
                    base_criteria_is_matched = True
                    self.append_new_match(tuuid, token_matched, **kwargs)

                file_affected_is_a_config, affected_file_ext = self.affected_file_is_a_config(affected_file)
                config_threshold = self.extensions_with_extra_checks[
                    affected_file_ext] if file_affected_is_a_config else self.valid_hash_length

                if not base_criteria_is_matched and file_affected_is_a_config \
                        and self.token_matches_config_token_criteria(token_matched, config_threshold):
                    self.append_new_match(tuuid, token_matched, **kwargs)

        self.store_results(self.stored_matches)

    def retrieve_and_scan_repo(self):
        """
        Attempt to clone a repo, if repo is already cloned; pull the latest commit
        """
        last_known_commit = None

        with self.DB_CONN as wn_cursor:
            # Retrieve last scan timestamp from Blobs
            last_scan_qry = wn_cursor.execute(
                """
                SELECT datetime(max(date_found), 'localtime') from Blobs
                """
            ).fetchone()
            last_blob_scan_date = last_scan_qry[0]
            self.new_blob_last_logged_at = self._date_from_string(last_blob_scan_date)

            # Retrieve last scan timestamp from Tokens
            last_scan_qry = wn_cursor.execute(
                """
                SELECT datetime(max(date_found), 'localtime') from Tokens
                """
            ).fetchone()
            last_token_scan_date = last_scan_qry[0]
            self.new_token_last_logged_at = self._date_from_string(last_token_scan_date)

        # Loop through each domain in targets.yaml
        for github_domain, github_config in Cerebro.yaml_loader(self.scan_targets).items():
            # This is the optional authentication github token you can add, see
            #  https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/
            env_name_for_github_token = github_config.get("environment_variable_token_name")
            if env_name_for_github_token:
                github_token = os.environ.get(env_name_for_github_token, "ENV_VARIABLE_NOT_SET")
                github_url = "https://{token}@{domain}/".format(token=github_token, domain=github_domain)
            else:
                github_url = "https://{domain}/".format(domain=github_domain)

            repo_names_list = github_config.get("repositories",[])
            repo_path_and_name = [(''.join([github_url, repo_name]), repo_name,) for repo_name in repo_names_list]
            for remote_path, repo_name in repo_path_and_name:
                has_diff = False
                local_path = os.path.join(self.REPOS_BASE_DIR, github_domain, repo_name, "master")
                if isdir(local_path):
                    last_known_commit = self.get_latest_commit(local_path)

                    # Update repo and get latest commit
                    chdir(local_path)

                    p = subprocess.Popen(["git","clean","-fxd"], stdout=subprocess.PIPE)
                    (output, err) = p.communicate()
                    p_status = p.wait()

                    p = subprocess.Popen(["git","reset"], stdout=subprocess.PIPE)
                    (output, err) = p.communicate()
                    p_status = p.wait()

                    p = subprocess.Popen(["git","pull","-f","origin","master"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    (output, err) = p.communicate()
                    p_status = p.wait()

                    latest_commit = self.get_latest_commit(local_path)

                    if last_known_commit != latest_commit:
                        has_diff = True
                        self.prepare_diff_for_scan(github_domain, repo_name, last_known_commit, latest_commit)
                        print('Diffs found for {}'.format(repo_name))

                    chdir(Cerebro.CEREBRO_DIR)
                else:
                    try:
                        Repo.clone_from(remote_path, local_path)
                        last_known_commit = self.get_latest_commit(local_path)
                    except GitCommandError as e:
                        print('Failed to clone repo {0}: {1}'.format(e, remote_path))

                if has_diff:
                    target_directory = os.path.join(self.DIFF_BASE_DIR, github_domain, repo_name, "master")
                else:
                    target_directory = os.path.join(self.REPOS_BASE_DIR, github_domain, repo_name, "master")

                raw_results = self.run_scan(target_directory)

                # Process and store raw_results
                params = {'repo_name': repo_name, 'commit_hash': last_known_commit}
                self.process_results(raw_results, **params)

    def replace_local_filepath_with_remote_filepath(self, repo_name, local_filepath):
        local_filepath = str(local_filepath).replace(Cerebro.CEREBRO_DIR, '')
        local_filepath = str(local_filepath).replace('/wn_diffs', '')
        remote_filepath = local_filepath.replace(repo_name, '{0}{1}'.format(repo_name, '/blob/master'))
        return remote_filepath

    def _date_from_string(self, input_date_string):
        if input_date_string:
            return datetime.strptime(input_date_string, '%Y-%m-%d %H:%M:%S')

        return datetime.today()

    def get_scan_results(self):
        """
        Build an object suitable for reporting via Slack and/or Dashboard.
        :return: tuple (tokens_found, blobs_affected_by_repo,)
        """
        with self.DB_CONN as wn_cursor:
            tokens_qry = wn_cursor.execute(
                """
                SELECT tuuid, token, datetime(date_found, 'localtime') FROM Tokens WHERE is_false_positive = 'false'
                """
            ).fetchall()
            tokens_found = [
                self.TOKEN(
                    tuuid=token_tuple[0],
                    token=str(token_tuple[1]),
                    date_found=self._date_from_string(token_tuple[2])
                )
                for token_tuple in tokens_qry
            ]

            blobs_query = wn_cursor.execute(
                """
                SELECT repo_name, muuid, filename, row_number, datetime(date_found, 'localtime') FROM Blobs
                WHERE repo_name is not '' and is_false_positive = 'false'
                """
            ).fetchall()
            blobs_affected_by_repo = {str(name): [] for name in set(blob[0] for blob in blobs_query)}
            for blob in blobs_query:
                for name in blobs_affected_by_repo.keys():
                    if name == str(blob[0]):
                        blobs_affected_by_repo[str(blob[0])].append(
                            self.BLOB(
                                muuid=str(blob[1]),
                                filepath=self.replace_local_filepath_with_remote_filepath(name, blob[2]),
                                row_number=blob[3],
                                date_found=self._date_from_string(blob[4])
                            )
                        )

        return tokens_found, blobs_affected_by_repo

    def results_summary(self):
        """
        Build findings for Dashboard
        :return: list of dictionaries
        """
        results_summary = []
        _, blobs_affected_by_repo = self.get_scan_results()
        for repo_name, details in blobs_affected_by_repo.items():
            results_summary.append(
                {
                    'match': {
                        'name': repo_name,
                        'count': len(blobs_affected_by_repo[repo_name]),
                        'details': blobs_affected_by_repo[repo_name]
                    }
                }
            )

        return results_summary

    def notify_slack(self):
        """
        Notify Slack channel of findings, slack webhook & username set in
        environmental variables, see README
        """
        tokens_found, blobs_affected_by_repo = self.get_scan_results()
        new_tokens = set(
            token.tuuid
            for token in tokens_found
            if token.date_found > self.new_token_last_logged_at
        )

        new_tokens_found_text = '*{0}* new tokens found in repos since {1}.\n'.format(
            len(new_tokens), self.new_token_last_logged_at
        )

        new_blobs = []
        for repo_name in blobs_affected_by_repo.keys():
            for blob in blobs_affected_by_repo[repo_name]:
                if blob.date_found > self.new_blob_last_logged_at:
                    new_blobs.append(blob.muuid)

        new_blobs_found_text = '*{0}* new blobs found in repos since last find on {1}.\n'.format(
            len(set(new_blobs)), self.new_blob_last_logged_at
        )

        payload_text = '\n\nSummary of findings so far:\n'
        payload_text += '\n'.join(
            ["{0} item(s) found in {1}".format(len(blobs_affected_by_repo[repo_name]), repo_name) for repo_name in
             blobs_affected_by_repo.keys()]
        )

        payload = {
            "channel": os.environ.get('SLACK_CHANNEL_OR_USER'),
            "username": "cerebro",
            "text": new_tokens_found_text + new_blobs_found_text + payload_text + payload_footer
        }
        post(os.environ.get('SLACK_API_URL'), json=payload)
