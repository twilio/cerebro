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

from math import log

def shannons_entropy_batch(base64_chars, hex_chars, data_list, character_set):
    """
    Original concept here http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    Adapted from https://github.com/dxa4481/truffleHog/blob/master/truffleHog.py
    :param <list> data_list
    :return: integer
    """
    entropy = 0
    desired_entropy_levels = {
        base64_chars: entropy > 4.5,
        hex_chars: entropy > 3.0
    }
    for data in data_list:
        if not data:
            continue
        for x in (ord(c) for c in character_set):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * log(p_x, 2)

        if desired_entropy_levels[character_set]:
            break  # exit loop on first match of desired entropy level

    return entropy
