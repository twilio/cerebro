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

import mock
import pytest

from os import getcwd, unlink, environ
from git import Repo
from shutil import rmtree
from tempfile import mkstemp
from distutils.util import strtobool
from cerebro.cerebro import Cerebro
from truffleHog.truffleHog import get_strings_of_set

class TestCerebro(object):

    MOCK_REPO_DIR = None
    TEST_SCAN_RESULTS_FILE = None

    @pytest.fixture
    def cerebro_object(self):
        environ["CEREBRO_DATABASE_URL"] = ":memory:"
        cerebro_object = Cerebro()
        return cerebro_object

    @pytest.fixture
    def raw_results(self):
        _, test_scan_results = mkstemp(suffix=".txt")
        __class__.TEST_SCAN_RESULTS_FILE = test_scan_results
        with open(test_scan_results, 'w') as test_results_handle:
            test_results_handle.write(
                """
                security/gitrob_test_repo/api_keys.txt:1:0:   API_KEY="BIa827cd007eeeeda43333533f92db6408"
                security/gitrob_test_repo/api_keys.txt:2:48:secret="15a827cd007eeeeda43333533f92db6408"
                security/gitrob_test_repo/api_keys.txt:4:93:apikey="91a827cd007eeeeda43333533f92db6408"
                security/gitrob_test_repo/diff10.txt:1:0:password  = 'HsGNcJyj9xjkZnnKkWlcSzAY1jFKfI2X'
                security/gitrob_test_repo/diff10.txt:2:47:password='asGNcJyj9xjkZnnKkWlcSzAY1jFKfI2X'
                security/gitrob_test_repo/dummy_private_key.pem:1:0:-----BEGIN RSA PRIVATE KEY-----
                security/gitrob_test_repo/dummy_private_key.pem:14:696:-----END RSA PRIVATE KEY-----
                security/gitrob_test_repo/TreasureBox/hidden.txt:1:0:secret_key = "39600b10a68dc31f0b9e3d90addec17d"
                security/gitrob_test_repo/TreasureBox/hidden.txt:2:48:secret_key="39600b10a68dc31f0b9e3d90addec17d"
                security/gitrob_test_repo/TreasureBox/hidden.txt:3:94:secret_key= "39600b10a68dc31f0b9e3d90addec17d"
                security/gitrob_test_repo/upperAndLowercase.conf:1:0:password = someCamelCaseAndIsGreaterThanThirtyXtersAndNoQoutes
                security/gitrob_test_repo/upperAndLowercase.conf:3:92:-----END PRIVATE KEY-----
                security/gitrob_test_repo/upperAndLowercase.conf:3:92:------END PRIVATE KEY------
                security/gitrob_test_repo/password.conf:3:92:       API_KEY="11a827cd007eeeeda43333533f92db6408"
                security/gitrob_test_repo/passwords.ini:1:0:smsc-password = lskdjqwe #correct
                security/gitrob_test_repo/passwords.conf:2:34:smscPassword = lskdjqwe #correct
                security/gitrob_test_repo/upperAndLowercase.yaml:2:63:password = Qbsepu@2msdfs9
                """
            )

        return open(test_scan_results, 'r')

    def create_test_tokens_and_blobs(self, cerebro_object):
        test_tokens_by_uuids = [
            ('token_001', '91a827cd007eeeeda43333533f92db6408',),
            ('token_002', '15a827cd007eeeeda43333533f92db6408',),
            ('token_003', 'HsGNcJyj9xjkZnnKkWlcSzAY1jFKfI2X',),
        ]

        test_blobs_by_uuids = [
            ('blob_001', 'token_001', 'repo1', 'aa3edfg', 'file1.txt', '3'),
            ('blob_002', 'token_002', 'repo2', 'bc3edhi', 'file2.txt', '4'),
            ('blob_003', 'token_003', 'repo3', 'de3edjk', 'file3.txt', '5'),
        ]

        with cerebro_object.DB_CONN as wn_cursor:
            wn_cursor.executemany(
                """
                INSERT INTO Tokens(tuuid, token) VALUES (?, ?)
                """,
                test_tokens_by_uuids
            )
            wn_cursor.commit()

            wn_cursor.executemany(
                """
                INSERT INTO Blobs(muuid, tuuid_fk, repo_name, commit_hash, filename, row_number)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                test_blobs_by_uuids
            )
            wn_cursor.commit()

    @pytest.fixture
    def mock_repo(self):
        working_dir = "/".join([getcwd(), 'tests/mock_repo'])
        mock_repo = Repo.init(working_dir, mkdir=True)
        __class__.MOCK_REPO_DIR = working_dir
        return mock_repo

    def mock_repo_add_content(self, mock_repo, new_content):
        _, test_file_name = mkstemp(suffix=".test", dir=mock_repo.working_dir)
        with open(test_file_name, 'w') as file_handle:
            file_handle.write(new_content)

        mock_repo.head.reset()
        mock_repo.index.add([test_file_name])
        mock_repo.index.commit('Add test file')

        return mock_repo

    def mock_repo_clear_entries(self, mock_repo):
        mock_repo.index.entries.clear()
        return mock_repo

    # Test that our SID patterns are ignored.
    sid_data_provider = [
        ('21203i2032n9293i2nskdsddksdsdsds923232', False),
        ('XJ203i2032n9293i2nskdsddksdsdsds923232', True),
        ('DH203i2032n9293i2nskdsddksdsdsds923232', True),
        ("S3_ACCESS_KEY = 'AKIAIPS6S7546ZDKUICA'", False),
        ('   API_KEY="BIa827cd007eeeeda43333533f92db6408"', False),
        ('', False)
    ]

    @pytest.mark.parametrize("input_string, expected_boolean", sid_data_provider)
    def test_sid_is_ignored(self, input_string, expected_boolean, cerebro_object):
        assert cerebro_object.token_matches_regexes_ignored(input_string) is expected_boolean

    def test_token_contains_private_key_matches_private_keys(self, cerebro_object):
        test_string = """
                -----begin rsa PRIVATE KEY-----

        some keylike stuff here
        """
        assert cerebro_object.token_matches_regexes_sought(test_string) is True

    def test_token_contains_private_key_ignores_non_private_keys(self, cerebro_object):
        test_string = """
                -----begin rsa public key-----

        some keylike stuff here
        """
        assert cerebro_object.token_matches_regexes_sought(test_string) is False

    def test_token_contains_private_key_ignores_end_private_key_line(self, cerebro_object):
        test_string = """
                -----end rsa private key-----

        some keylike stuff here
        """
        assert cerebro_object.token_matches_regexes_sought(test_string) is False

    def test_token_contains_private_key_ignores_end_private_key_line2(self, cerebro_object):
        test_string = """
                -----end private key-----

        some keylike stuff here
        """
        assert cerebro_object.token_matches_regexes_sought(test_string) is False

    def test_token_has_sufficient_entropy_ignores_strings_with_little_entropy(self, cerebro_object):
        test_string = 'not much entropy here'
        assert cerebro_object.token_has_sufficient_entropy(test_string) is False

    def test_token_has_sufficient_entropy_matches_strings_with_good_entropy(self, cerebro_object):
        test_string = cerebro_object.base64_chars
        assert cerebro_object.token_has_sufficient_entropy(test_string) is True

    def test_token_has_sufficient_entropy_matches_strings_with_good_entropy2(self, cerebro_object):
        test_string = cerebro_object.hex_chars
        assert cerebro_object.token_has_sufficient_entropy(test_string) is True

    def test_processes_results(self, cerebro_object, raw_results):
        cerebro_object.stored_matches = []
        kwargs = {'repo_name': 'security/gitrob_test_repo', 'commit_hash': '8a29shs'}
        cerebro_object.process_results(raw_results, **kwargs)
        assert len(cerebro_object.stored_matches) == 13

    def test_token_has_valid_length_and_number(self, cerebro_object):
        test_string = 'very short string'
        assert cerebro_object.token_has_valid_length_and_number(test_string) is False

        test_string2 = '91a827cd007eeeeda43333533f92db6408'
        assert cerebro_object.token_has_valid_length_and_number(test_string2) is True

    def test_get_latest_commit(self, mock_repo, cerebro_object):
        mock_repo_with_content = self.mock_repo_add_content(mock_repo, 'Dummy content')
        post_commit_sha = mock_repo_with_content.head.commit.hexsha[0:7]  # need to compare with shorter format

        assert str(post_commit_sha) == cerebro_object.get_latest_commit(mock_repo.working_dir)

    def test_build_where_in_clause(self, cerebro_object):
        test_iterable = ('a', 'b', 'c',)
        expected_wherein = '"a", "b", "c"'
        assert expected_wherein == cerebro_object.build_where_in_clause(test_iterable)

    def test_mark_tokens_and_blobs_as_false_positive(self, cerebro_object):
        self.create_test_tokens_and_blobs(cerebro_object)
        blob_002_muuid = ['blob_002']
        blob_002_tuuid_fk = 'token_002'
        cerebro_object.mark_tokens_and_blobs_as_false_positive(blob_002_muuid)

        with cerebro_object.DB_CONN as wn_cursor:
            test_token_qry = "SELECT is_false_positive FROM Tokens WHERE tuuid = '{0}'".format(blob_002_tuuid_fk)
            token_002 = wn_cursor.execute(test_token_qry)
            token_002_is_false_positive = token_002.fetchall()[0]

            assert strtobool(token_002_is_false_positive[0]) == 1

            test_blob_qry = "SELECT is_false_positive FROM Blobs WHERE muuid = '{0}'".format(blob_002_muuid[0])
            blob_002 = wn_cursor.execute(test_blob_qry)
            blob_002_is_false_positive = blob_002.fetchall()[0]

            assert strtobool(blob_002_is_false_positive[0]) == 1

    def test_affected_file_is_a_config(self, cerebro_object):
        test_filename_1 = 'somefile.py'
        test_filename_2 = 'somefile.conf'
        assert cerebro_object.affected_file_is_a_config(test_filename_1)[0] is False
        assert cerebro_object.affected_file_is_a_config(test_filename_2)[0] is True

    strings_data_provider = [
        ('some text', 20, 0),  # test short string with little entropy
        ('some text that is more than twenty characters long', 20, 0),  # test randomly long string with little entropy
        ('asGNcJyj9xjkZnnKkWlcSzAY1jFKfI2X', 20, 1),  # test standard culprit
        ('lskdjqwe', 6, 1),  # test shorter strings from config files for entropy
    ]

    @pytest.mark.parametrize("sample_text, threshold, compare_length", strings_data_provider)
    def test_get_strings_of_set_returns_at_desired_threshold(self, sample_text, threshold, compare_length,
                                                             cerebro_object):
        actual_result = get_strings_of_set(sample_text, cerebro_object.base64_chars, threshold)
        if compare_length == 0:
            assert len(actual_result) == 0
        else:
            assert len(actual_result[0]) > compare_length

    filepaths_data_provider = [
        # test full repo scan
        (
            '/'.join([getcwd(), 'test_organization/test_repo/org_name1/repo_name1/filename1.ext']),
            '/test_organization/test_repo/blob/master/org_name1/repo_name1/filename1.ext',
        ),
        # test repo diff scan
        (
            '/'.join([getcwd(), 'test_organization/test_repo/wn_diffs/org_name1/repo_name1/filename1.ext']),
            '/test_organization/test_repo/blob/master/org_name1/repo_name1/filename1.ext',
        ),
    ]

    @pytest.mark.parametrize("local_filepath, remote_filepath", filepaths_data_provider)
    def test_replace_local_filepath_with_remote_filepath(self, local_filepath, remote_filepath, cerebro_object):
        actual_repo_path = cerebro_object.replace_local_filepath_with_remote_filepath('test_organization/test_repo',
                                                                                      local_filepath)
        assert remote_filepath == actual_repo_path

    def test_results_summary(self, cerebro_object):
        mock_tokens = [
            cerebro_object.TOKEN('tab35t', '39600b10a68dc31f0b9e3d90addec17d', '2017-01-11 11:30:00'),
            cerebro_object.TOKEN('tbc35t', '15a827cd007eeeeda43333533f92db6408', '2017-01-11 11:30:00'),
            cerebro_object.TOKEN('tde35t', 'HsGNcJyj9xjkZnnKkWlcSzAY1jFKfI2X', '2017-01-11 11:30:00'),
        ]
        mock_blobs_affected_by_repo = {
            'repo1': [
                cerebro_object.BLOB('mab35t', 'test_file1.txt', '5', '2017-01-11 11:30:00'),
                cerebro_object.BLOB('mgg41h', 'somefile1.txt', '21', '2017-01-11 11:30:00'),
            ],
            'repo2': [
                cerebro_object.BLOB('mjk93d', 'another_file1.txt', '469', '2017-01-11 11:30:00'),
            ]
        }

        cerebro_object.get_scan_results = mock.MagicMock()
        cerebro_object.get_scan_results.return_value = (mock_tokens, mock_blobs_affected_by_repo,)

        expected_results_summary = [
            {'match': {'name': 'repo1', 'count': 2, 'details': mock_blobs_affected_by_repo['repo1']}},
            {'match': {'name': 'repo2', 'count': 1, 'details': mock_blobs_affected_by_repo['repo2']}}
        ]

        actual_results_summary = cerebro_object.results_summary()
        expected_sorted = sorted(expected_results_summary, key=lambda k: k['match']['name'])
        actual_sorted = sorted(actual_results_summary, key=lambda k: k['match']['name'])
        assert expected_sorted == actual_sorted

    def test_results_as_json(self):
        test_result_list = [
            {
                'token_id': '85c5aa81b7e8c29bdfdabea34bafb9556b422ef8',
                'token': 'HsGNcJyj9xjkZnnKkWlcSzAY1jFKfI2X',
                'result_details':
                    {
                        'muuid': '3443a521d6c03963e704a15896edecf8a2e00e43',
                        'tuuid': '85c5aa81b7e8c29bdfdabea34bafb9556b422ef8',
                        'affected_file': 'affected_file_123.py',
                        'commit_hash': 'fe0120f',
                        'row_number': '18',
                        'repo_name': 'test_organization/test_repo/'
                    }
            }
        ]

        expected_results = {"results": [
            {
                "repo": "test_organization/test_repo/",
                "tokens_found": [
                    {
                        "affected_file": "affected_file_123.py",
                        "commit_hash": "fe0120f",
                        "line_number": "18",
                        "token": "HsGNcJyj9xjkZnnKkWlcSzAY1jFKfI2X"
                    }
                ]
            }
        ]}

        actual_results = Cerebro.results_as_json(test_result_list)
        assert expected_results == actual_results

    @classmethod
    def teardown_class(cls):
        rmtree(cls.MOCK_REPO_DIR)
        unlink(cls.TEST_SCAN_RESULTS_FILE)
