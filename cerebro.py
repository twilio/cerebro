#!/usr/bin/env python
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

from cerebro.cerebro import Cerebro
from argparse import ArgumentParser
from json import dumps

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-o", "--output", type=str, choices=["json", "slack"], default="json")
    args = parser.parse_args()

    wn = Cerebro()
    wn.retrieve_and_scan_repo()

    if args.output == "json":
        cerebro_results = Cerebro.results_as_json(wn.get_stored_matches())
        print(dumps(cerebro_results, indent=4, sort_keys=True))
    else:
        wn.notify_slack()
