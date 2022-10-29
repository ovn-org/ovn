#!/usr/bin/env python3
# Copyright (c) 2016, 2017 Red Hat, Inc.
# Copyright (c) 2018 Nicira, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import email
import getopt
import os
import re
import sys

RETURN_CHECK_INITIAL_STATE = 0
RETURN_CHECK_STATE_WITH_RETURN = 1
RETURN_CHECK_AWAITING_BRACE = 2
EXIT_FAILURE = 1
__errors = 0
__warnings = 0
empty_return_check_state = 0
print_file_name = None
checking_file = False
total_line = 0
colors = False
spellcheck = False
quiet = False
spell_check_dict = None
MAX_LINE_LEN = 79


def open_spell_check_dict():
    import enchant

    try:
        extra_keywords = ['ovs', 'vswitch', 'vswitchd', 'ovs-vswitchd',
                          'netdev', 'selinux', 'ovs-ctl', 'dpctl', 'ofctl',
                          'openvswitch', 'dpdk', 'hugepage', 'hugepages',
                          'pmd', 'upcall', 'vhost', 'rx', 'tx', 'vhostuser',
                          'openflow', 'qsort', 'rxq', 'txq', 'perf', 'stats',
                          'struct', 'int', 'char', 'bool', 'upcalls', 'nicira',
                          'bitmask', 'ipv4', 'ipv6', 'tcp', 'tcp4', 'tcpv4',
                          'udp', 'udp4', 'udpv4', 'icmp', 'icmp4', 'icmpv6',
                          'vlan', 'vxlan', 'cksum', 'csum', 'checksum',
                          'ofproto', 'numa', 'mempool', 'mempools', 'mbuf',
                          'mbufs', 'hmap', 'cmap', 'smap', 'dhcpv4', 'dhcp',
                          'dhcpv6', 'opts', 'metadata', 'geneve', 'mutex',
                          'netdev', 'netdevs', 'subtable', 'virtio', 'qos',
                          'policer', 'datapath', 'tunctl', 'attr', 'ethernet',
                          'ether', 'defrag', 'defragment', 'loopback', 'sflow',
                          'acl', 'initializer', 'recirc', 'xlated', 'unclosed',
                          'netlink', 'msec', 'usec', 'nsec', 'ms', 'us', 'ns',
                          'kilobits', 'kbps', 'kilobytes', 'megabytes', 'mbps',
                          'gigabytes', 'gbps', 'megabits', 'gigabits', 'pkts',
                          'tuple', 'miniflow', 'megaflow', 'conntrack',
                          'vlans', 'vxlans', 'arg', 'tpid', 'xbundle',
                          'xbundles', 'mbundle', 'mbundles', 'netflow',
                          'localnet', 'odp', 'pre', 'dst', 'dest', 'src',
                          'ethertype', 'cvlan', 'ips', 'msg', 'msgs',
                          'liveness', 'userspace', 'eventmask', 'datapaths',
                          'slowpath', 'fastpath', 'multicast', 'unicast',
                          'revalidation', 'namespace', 'qdisc', 'uuid',
                          'ofport', 'subnet', 'revalidation', 'revalidator',
                          'revalidate', 'l2', 'l3', 'l4', 'openssl', 'mtu',
                          'ifindex', 'enum', 'enums', 'http', 'https', 'num',
                          'vconn', 'vconns', 'conn', 'nat', 'memset', 'memcmp',
                          'strcmp', 'strcasecmp', 'tc', 'ufid', 'api',
                          'ofpbuf', 'ofpbufs', 'hashmaps', 'hashmap', 'deref',
                          'dereference', 'hw', 'prio', 'sendmmsg', 'sendmsg',
                          'malloc', 'free', 'alloc', 'pid', 'ppid', 'pgid',
                          'uid', 'gid', 'sid', 'utime', 'stime', 'cutime',
                          'cstime', 'vsize', 'rss', 'rsslim', 'whcan', 'gtime',
                          'eip', 'rip', 'cgtime', 'dbg', 'gw', 'sbrec', 'bfd',
                          'sizeof', 'pmds', 'nic', 'nics', 'hwol', 'encap',
                          'decap', 'tlv', 'tlvs', 'decapsulation', 'fd',
                          'cacheline', 'xlate', 'skiplist', 'idl',
                          'comparator', 'natting', 'alg', 'pasv', 'epasv',
                          'wildcard', 'nated', 'amd64', 'x86_64',
                          'recirculation', 'linux', 'afxdp', 'promisc', 'goto',
                          'misconfigured', 'misconfiguration', 'checkpatch',
                          'debian', 'travis', 'cirrus', 'appveyor', 'faq',
                          'erspan', 'const', 'hotplug', 'addresssanitizer',
                          'ovsdb', 'dpif', 'veth', 'rhel', 'jsonrpc', 'json',
                          'syscall', 'lacp', 'ipf', 'skb', 'valgrind']

        global spell_check_dict
        spell_check_dict = enchant.Dict("en_US")
        for kw in extra_keywords:
            spell_check_dict.add(kw)

        return True
    except:
        return False


def get_color_end():
    global colors
    if colors:
        return "\033[00m"
    return ""


def get_red_begin():
    global colors
    if colors:
        return "\033[91m"
    return ""


def get_yellow_begin():
    global colors
    if colors:
        return "\033[93m"
    return ""


def print_error(message):
    global __errors
    print("%sERROR%s: %s" % (get_red_begin(), get_color_end(), message))

    __errors = __errors + 1


def print_warning(message):
    global __warnings
    print("%sWARNING%s: %s" % (get_yellow_begin(), get_color_end(), message))

    __warnings = __warnings + 1


def reset_counters():
    global __errors, __warnings, total_line

    __errors = 0
    __warnings = 0
    total_line = 0


# These are keywords whose names are normally followed by a space and
# something in parentheses (usually an expression) then a left curly brace.
#
# 'do' almost qualifies but it's also used as "do { ... } while (...);".
__parenthesized_constructs = 'if|for|while|switch|[_A-Z]+FOR_*EACH[_A-Z0-9]*'

__regex_added_line = re.compile(r'^\+{1,2}[^\+][\w\W]*')
__regex_subtracted_line = re.compile(r'^\-{1,2}[^\-][\w\W]*')
__regex_leading_with_whitespace_at_all = re.compile(r'^\s+')
__regex_leading_with_spaces = re.compile(r'^ +[\S]+')
__regex_trailing_whitespace = re.compile(r'[^\S]+$')
__regex_single_line_feed = re.compile(r'^\f$')
__regex_for_if_missing_whitespace = re.compile(r' +(%s)[\(]'
                                               % __parenthesized_constructs)
__regex_hash_define_for_each = re.compile(
    r'#define [_A-Z]+FOR_*EACH[_A-Z0-9]*\(')
__regex_for_if_too_much_whitespace = re.compile(r' +(%s)  +[\(]'
                                                % __parenthesized_constructs)
__regex_for_if_parens_whitespace = \
    re.compile(r' +(%s) \( +[\s\S]+\)' % __parenthesized_constructs)
__regex_is_for_if_single_line_bracket = \
    re.compile(r'^ +(%s) \(.*\)' % __parenthesized_constructs)
__regex_ends_with_bracket = \
    re.compile(r'[^\s]\) {(\s+/\*[\s\Sa-zA-Z0-9\.,\?\*/+-]*)?$')
__regex_ptr_declaration_missing_whitespace = re.compile(r'[a-zA-Z0-9]\*[^*]')
__regex_cast_missing_whitespace = re.compile(r'\)[a-zA-Z0-9]')
__regex_is_comment_line = re.compile(r'^\s*(/\*|\*\s)')
__regex_has_comment = re.compile(r'.*(/\*|\*\s)')
__regex_has_c99_comment = re.compile(r'.*//.*$')
__regex_trailing_operator = re.compile(r'^[^ ]* [^ ]*[?:]$')
__regex_conditional_else_bracing = re.compile(r'^\s*else\s*{?$')
__regex_conditional_else_bracing2 = re.compile(r'^\s*}\selse\s*$')
__regex_has_xxx_mark = re.compile(r'.*xxx.*', re.IGNORECASE)
__regex_added_doc_rst = re.compile(
                    r'\ndiff .*Documentation/.*rst\nnew file mode')
__regex_empty_return = re.compile(r'\s*return;')
__regex_if_macros = re.compile(r'^ +(%s) \([\S]([\s\S]+[\S])*\) { +\\' %
                               __parenthesized_constructs)
__regex_nonascii_characters = re.compile("[^\u0000-\u007f]")
__regex_efgrep = re.compile(r'.*[ef]grep.*$')

skip_leading_whitespace_check = False
skip_trailing_whitespace_check = False
skip_gerrit_change_id_check = False
skip_block_whitespace_check = False
skip_signoff_check = False

# Don't enforce character limit on files that include these characters in their
# name, as they may have legitimate reasons to have longer lines.
#
# Python isn't checked as flake8 performs these checks during build.
line_length_blacklist = re.compile(
    r'\.(am|at|etc|in|m4|mk|patch|py)$|^debian/.*$')

# Don't enforce a requirement that leading whitespace be all spaces on
# files that include these characters in their name, since these kinds
# of files need lines with leading tabs.
leading_whitespace_blacklist = re.compile(r'\.(mk|am|at)$|^debian/.*$')


def is_subtracted_line(line):
    """Returns TRUE if the line in question has been removed."""
    return __regex_subtracted_line.search(line) is not None


def is_added_line(line):
    """Returns TRUE if the line in question is an added line.
    """
    global checking_file
    return __regex_added_line.search(line) is not None or checking_file


def added_line(line):
    """Returns the line formatted properly by removing diff syntax"""
    global checking_file
    if not checking_file:
        return line[1:]
    return line


def leading_whitespace_is_spaces(line):
    """Returns TRUE if the leading whitespace in added lines is spaces
    """
    if skip_leading_whitespace_check:
        return True
    if (__regex_leading_with_whitespace_at_all.search(line) is not None and
            __regex_single_line_feed.search(line) is None):
        return __regex_leading_with_spaces.search(line) is not None

    return True


def trailing_whitespace_or_crlf(line):
    """Returns TRUE if the trailing characters is whitespace
    """
    if skip_trailing_whitespace_check:
        return False
    return (__regex_trailing_whitespace.search(line) is not None and
            __regex_single_line_feed.search(line) is None)


def if_and_for_whitespace_checks(line):
    """Return TRUE if there is appropriate whitespace after if, for, while
    """
    if skip_block_whitespace_check:
        return True
    if (__regex_for_if_missing_whitespace.search(line) is not None and
        __regex_hash_define_for_each.search(line) is None):
        return False
    if (__regex_for_if_too_much_whitespace.search(line) is not None or
        __regex_for_if_parens_whitespace.search(line)):
        return False
    return True


def if_and_for_end_with_bracket_check(line):
    """Return TRUE if there is a bracket at the end of an if, for, while
       block which fits on a single line ie: 'if (foo)'"""

    def balanced_parens(line):
        """This is a rather naive counter - it won't deal with quotes"""
        balance = 0
        for letter in line:
            if letter == '(':
                balance += 1
            elif letter == ')':
                balance -= 1
        return balance == 0

    if __regex_is_for_if_single_line_bracket.search(line) is not None:
        if not balanced_parens(line):
            return True

        # Early return to avoid potential catastrophic backtracking in the
        # __regex_if_macros regex
        if len(line) == MAX_LINE_LEN - 1 and line[-1] == ')':
            return True

        if __regex_ends_with_bracket.search(line) is None and \
           __regex_if_macros.match(line) is None:
            return False
    if __regex_conditional_else_bracing.match(line) is not None:
        return False
    if __regex_conditional_else_bracing2.match(line) is not None:
        return False
    return True


def pointer_whitespace_check(line):
    """Return TRUE if there is no space between a pointer name and the
       asterisk that denotes this is a apionter type, ie: 'struct foo*'"""
    return __regex_ptr_declaration_missing_whitespace.search(line) is not None


def nonascii_character_check(line):
    """Return TRUE if inappropriate Unicode characters are detected """
    return __regex_nonascii_characters.search(line) is not None


def cast_whitespace_check(line):
    """Return TRUE if there is no space between the '()' used in a cast and
       the expression whose type is cast, i.e.: '(void *)foo'"""
    return __regex_cast_missing_whitespace.search(line) is not None


def line_length_check(line):
    """Return TRUE if the line length is too long"""
    if len(line) > MAX_LINE_LEN:
        print_warning("Line is %d characters long (recommended limit is %d)"
                      % (len(line), MAX_LINE_LEN))
        return True
    return False


def is_comment_line(line):
    """Returns TRUE if the current line is part of a block comment."""
    return __regex_is_comment_line.match(line) is not None


def has_comment(line):
    """Returns TRUE if the current line contains a comment or is part of
       a block comment."""
    return __regex_has_comment.match(line) is not None


def has_c99_comment(line):
    """Returns TRUE if the current line contains C99 style comment (//)."""
    return __regex_has_c99_comment.match(line) is not None


def trailing_operator(line):
    """Returns TRUE if the current line ends with an operatorsuch as ? or :"""
    return __regex_trailing_operator.match(line) is not None


def has_xxx_mark(line):
    """Returns TRUE if the current line contains 'xxx'."""
    return __regex_has_xxx_mark.match(line) is not None


def has_efgrep(line):
    """Returns TRUE if the current line contains 'egrep' or 'fgrep'."""
    return __regex_efgrep.match(line) is not None


def filter_comments(current_line, keep=False):
    """remove all of the c-style comments in a line"""
    STATE_NORMAL = 0
    STATE_COMMENT_SLASH = 1
    STATE_COMMENT_CONTENTS = 3
    STATE_COMMENT_END_SLASH = 4

    state = STATE_NORMAL
    sanitized_line = ''
    check_state = STATE_NORMAL
    only_whitespace = True

    if keep:
        check_state = STATE_COMMENT_CONTENTS

    for c in current_line:
        if c == '/':
            if state == STATE_NORMAL:
                state = STATE_COMMENT_SLASH
            elif state == STATE_COMMENT_SLASH:
                # This is for c++ style comments.  We will warn later
                return sanitized_line[:1]
            elif state == STATE_COMMENT_END_SLASH:
                c = ''
                state = STATE_NORMAL
        elif c == '*':
            if only_whitespace:
                # just assume this is a continuation from the previous line
                # as a comment
                state = STATE_COMMENT_END_SLASH
            elif state == STATE_COMMENT_SLASH:
                state = STATE_COMMENT_CONTENTS
                sanitized_line = sanitized_line[:-1]
            elif state == STATE_COMMENT_CONTENTS:
                state = STATE_COMMENT_END_SLASH
        elif state == STATE_COMMENT_END_SLASH:
            # Need to re-introduce the star from the previous state, since
            # it may have been clipped by the state check below.
            c = '*' + c
            state = STATE_COMMENT_CONTENTS
        elif state == STATE_COMMENT_SLASH:
            # Need to re-introduce the slash from the previous state, since
            # it may have been clipped by the state check below.
            c = '/' + c
            state = STATE_NORMAL

        if state != check_state:
            c = ''

        if not c.isspace():
            only_whitespace = False

        sanitized_line += c

    return sanitized_line


def check_spelling(line, comment):
    if not spell_check_dict or not spellcheck:
        return False

    words = filter_comments(line, True) if comment else line
    words = words.replace(':', ' ').split(' ')

    for word in words:
        skip = False
        strword = re.subn(r'\W+', '', word)[0].replace(',', '')
        if (len(strword)
                and not spell_check_dict.check(strword.lower())
                and not spell_check_dict.check(word.lower())):
            if any([check_char in word
                    for check_char in ['=', '(', '-', '_', '/', '\'']]):
                skip = True

            # special case the '.'
            if '.' in word and not word.endswith('.'):
                skip = True

            # skip proper nouns and references to macros
            if strword.isupper() or (strword[0].isupper() and
                                     strword[1:].islower()):
                skip = True

            # skip words containing numbers
            if any(check_char.isdigit() for check_char in strword):
                skip = True

            if not skip:
                print_warning("Check for spelling mistakes (e.g. \"%s\")"
                              % strword)
                return True

    return False


def __check_doc_is_listed(text, doctype, docdir, docfile):
    if doctype == 'rst':
        beginre = re.compile(r'\+\+\+.*{}/index.rst'.format(docdir))
        docre = re.compile(r'\n\+.*{}'.format(docfile.replace('.rst', '')))
    elif doctype == 'automake':
        beginre = re.compile(r'\+\+\+.*Documentation/automake.mk')
        docre = re.compile(r'\n\+\t{}/{}'.format(docdir, docfile))
    else:
        raise NotImplementedError("Invalid doctype: {}".format(doctype))

    res = beginre.search(text)
    if res is None:
        return True

    hunkstart = res.span()[1]
    hunkre = re.compile(r'\n(---|\+\+\+) (\S+)')
    res = hunkre.search(text[hunkstart:])
    if res is None:
        hunkend = len(text)
    else:
        hunkend = hunkstart + res.span()[0]

    hunk = text[hunkstart:hunkend]
    # find if the file is being added.
    if docre.search(hunk) is not None:
        return False

    return True


def __check_new_docs(text, doctype):
    """Check if the documentation is listed properly. If doctype is 'rst' then
       the index.rst is checked. If the doctype is 'automake' then automake.mk
       is checked. Returns TRUE if the new file is not listed."""
    failed = False
    new_docs = __regex_added_doc_rst.findall(text)
    for doc in new_docs:
        docpathname = doc.split(' ')[2]
        gitdocdir, docfile = os.path.split(docpathname.rstrip('\n'))
        if docfile == "index.rst":
            continue

        if gitdocdir.startswith('a/'):
            docdir = gitdocdir.replace('a/', '', 1)
        else:
            docdir = gitdocdir

        if __check_doc_is_listed(text, doctype, docdir, docfile):
            if doctype == 'rst':
                print_warning("New doc {} not listed in {}/index.rst".format(
                              docfile, docdir))
            elif doctype == 'automake':
                print_warning("New doc {} not listed in "
                              "Documentation/automake.mk".format(docfile))
            else:
                raise NotImplementedError("Invalid doctype: {}".format(
                                          doctype))

            failed = True

    return failed


def check_doc_docs_automake(text):
    return __check_new_docs(text, 'automake')


def check_new_docs_index(text):
    return __check_new_docs(text, 'rst')


def empty_return_with_brace(line):
    """Returns TRUE if a function contains a return; followed
       by one or more line feeds and terminates with a '}'
       at start of line"""

    def empty_return(line):
        """Returns TRUE if a function has a 'return;'"""
        return __regex_empty_return.match(line) is not None

    global empty_return_check_state
    if empty_return_check_state == RETURN_CHECK_INITIAL_STATE \
       and empty_return(line):
        empty_return_check_state = RETURN_CHECK_STATE_WITH_RETURN
    elif empty_return_check_state == RETURN_CHECK_STATE_WITH_RETURN \
         and (re.match(r'^}$', line) or len(line) == 0):
        if re.match('^}$', line):
            empty_return_check_state = RETURN_CHECK_AWAITING_BRACE
    else:
        empty_return_check_state = RETURN_CHECK_INITIAL_STATE

    if empty_return_check_state == RETURN_CHECK_AWAITING_BRACE:
        empty_return_check_state = RETURN_CHECK_INITIAL_STATE
        return True

    return False


file_checks = [
        {'regex': __regex_added_doc_rst,
         'check': check_new_docs_index},
        {'regex': __regex_added_doc_rst,
         'check': check_doc_docs_automake}
]

checks = [
    {'regex': None,
     'match_name': lambda x: not line_length_blacklist.search(x),
     'check': lambda x: line_length_check(x)},

    {'regex': None,
     'match_name': lambda x: not leading_whitespace_blacklist.search(x),
     'check': lambda x: not leading_whitespace_is_spaces(x),
     'print': lambda: print_warning("Line has non-spaces leading whitespace")},

    {'regex': None, 'match_name': None,
     'check': lambda x: trailing_whitespace_or_crlf(x),
     'print': lambda: print_warning("Line has trailing whitespace")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: not if_and_for_whitespace_checks(x),
     'print': lambda: print_error("Improper whitespace around control block")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: not if_and_for_end_with_bracket_check(x),
     'print': lambda: print_error("Inappropriate bracing around statement")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: pointer_whitespace_check(x),
     'print':
     lambda: print_error("Inappropriate spacing in pointer declaration")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'check': lambda x: nonascii_character_check(x),
     'print':
     lambda: print_error("Inappropriate non-ascii characters detected.")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: cast_whitespace_check(x),
     'print':
     lambda: print_error("Inappropriate spacing around cast")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: trailing_operator(x),
     'print':
     lambda: print_error("Line has '?' or ':' operator at end of line")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: has_comment(x),
     'check': lambda x: has_xxx_mark(x),
     'print': lambda: print_warning("Comment with 'xxx' marker")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': lambda x: has_c99_comment(x),
     'print': lambda: print_error("C99 style comment")},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: has_comment(x),
     'check': lambda x: check_spelling(x, True)},

    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'check': lambda x: empty_return_with_brace(x),
     'interim_line': True,
     'print':
     lambda: print_warning("Empty return followed by brace, consider omitting")
     },

    {'regex': r'(\.at|\.sh)$', 'match_name': None,
     'check': lambda x: has_efgrep(x),
     'print':
     lambda: print_error("grep -E/-F should be used instead of egrep/fgrep")},
]


def regex_function_factory(func_name):
    regex = re.compile(r'\b%s\([^)]*\)' % func_name)
    return lambda x: regex.search(x) is not None


def regex_error_factory(description):
    return lambda: print_error(description)


def regex_warn_factory(description):
    return lambda: print_warning(description)


std_functions = [
        ('malloc', 'Use xmalloc() in place of malloc()'),
        ('calloc', 'Use xcalloc() in place of calloc()'),
        ('realloc', 'Use xrealloc() in place of realloc()'),
        ('strdup', 'Use xstrdup() in place of strdup()'),
        ('asprintf', 'Use xasprintf() in place of asprintf()'),
        ('vasprintf', 'Use xvasprintf() in place of vasprintf()'),
        ('strcpy', 'Use ovs_strlcpy() in place of strcpy()'),
        ('strlcpy', 'Use ovs_strlcpy() in place of strlcpy()'),
        ('strncpy', 'Use ovs_strzcpy() in place of strncpy()'),
        ('strerror', 'Use ovs_strerror() in place of strerror()'),
        ('sleep', 'Use xsleep() in place of sleep()'),
        ('abort', 'Use ovs_abort() in place of abort()'),
        ('assert', 'Use ovs_assert() in place of assert()'),
        ('error', 'Use ovs_error() in place of error()'),
]

checks += [
    {'regex': r'(\.c|\.h)(\.in)?$',
     'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': regex_function_factory(function_name),
     'print': regex_error_factory(description)}
    for (function_name, description) in std_functions]

easy_to_misuse_api = [
        ('ovsrcu_barrier',
            'lib/ovs-rcu.c',
            'Are you sure you need to use ovsrcu_barrier(), '
            'in most cases ovsrcu_synchronize() will be fine?'),
        ]

checks += [
    {'regex': r'(\.c)(\.in)?$',
     'match_name': lambda x: x != location,
     'prereq': lambda x: not is_comment_line(x),
     'check': regex_function_factory(function_name),
     'print': regex_warn_factory(description)}
    for (function_name, location, description) in easy_to_misuse_api]


def regex_operator_factory(operator):
    regex = re.compile(r'^[^#][^"\']*[^ "]%s[^ "\'][^"]*' % operator)
    return lambda x: regex.search(filter_comments(x)) is not None


infix_operators = \
    [re.escape(op) for op in ['%', '<<', '>>', '<=', '>=', '==', '!=',
            '^', '|', '&&', '||', '?:', '=', '+=', '-=', '*=', '/=', '%=',
            '&=', '^=', '|=', '<<=', '>>=']] \
    + [r'[^<" ]<[^=" ]',
       r'[^\->" ]>[^=" ]',
       r'[^ !()/"]\*[^/]',
       r'[^ !&()"]&',
       r'[^" +(]\+[^"+;]',
       r'[^" \-(]\-[^"\->;]',
       r'[^" <>=!^|+\-*/%&]=[^"=]',
       r'[^* ]/[^* ]']
checks += [
    {'regex': r'(\.c|\.h)(\.in)?$', 'match_name': None,
     'prereq': lambda x: not is_comment_line(x),
     'check': regex_operator_factory(operator),
     'print': lambda: print_warning("Line lacks whitespace around operator")}
    for operator in infix_operators]


def get_file_type_checks(filename):
    """Returns the list of checks for a file based on matching the filename
       against regex."""
    global checks
    checkList = []
    for check in checks:
        regex_check = True
        match_check = True

        if check['regex'] is None and check['match_name'] is None:
            checkList.append(check)
            continue

        if check['regex'] is not None and \
           re.compile(check['regex']).search(filename) is None:
            regex_check = False

        if check['match_name'] is not None and \
                not check['match_name'](filename):
            match_check = False

        if regex_check and match_check:
            checkList.append(check)
    return checkList


def run_checks(current_file, line, lineno):
    """Runs the various checks for the particular line.  This will take
       filename into account."""
    global checking_file, total_line
    print_line = False
    for check in get_file_type_checks(current_file):
        if 'prereq' in check and not check['prereq'](line):
            continue
        if check['check'](line):
            if 'print' in check:
                check['print']()
            print_line = True

    if print_line:
        if checking_file:
            print("%s:%d:" % (current_file, lineno))
        else:
            print("#%d FILE: %s:%d:" % (total_line, current_file, lineno))
        print("%s\n" % line)


def interim_line_check(current_file, line, lineno):
    """Runs the various checks for the particular interim line.  This will
       take filename into account, and will check for the 'interim_line'
       key before running the check."""
    global checking_file, total_line
    print_line = False
    for check in get_file_type_checks(current_file):
        if 'prereq' in check and not check['prereq'](line):
            continue
        if 'interim_line' in check and check['interim_line']:
            if check['check'](line):
                if 'print' in check:
                    check['print']()
                    print_line = True

    if print_line:
        if checking_file:
            print("%s:%d:" % (current_file, lineno))
        else:
            print("#%d FILE: %s:%d:" % (total_line, current_file, lineno))
        print("%s\n" % line)


def run_file_checks(text):
    """Runs the various checks for the text."""
    for check in file_checks:
        if check['regex'].search(text) is not None:
            check['check'](text)


def ovs_checkpatch_parse(text, filename, author=None, committer=None):
    global print_file_name, total_line, checking_file, \
        empty_return_check_state

    PARSE_STATE_HEADING = 0
    PARSE_STATE_DIFF_HEADER = 1
    PARSE_STATE_CHANGE_BODY = 2

    lineno = 0
    signatures = []
    co_authors = []
    parse = 0
    current_file = filename if checking_file else ''
    previous_file = ''
    seppatch = re.compile(r'^---([\w]*| \S+)$')
    hunks = re.compile(r'^(---|\+\+\+) (\S+)')
    hunk_differences = re.compile(
        r'^@@ ([0-9-+]+),([0-9-+]+) ([0-9-+]+),([0-9-+]+) @@')
    is_author = re.compile(r'^(Author|From): (.*)$', re.I | re.M | re.S)
    is_committer = re.compile(r'^(Commit: )(.*)$', re.I | re.M | re.S)
    is_signature = re.compile(r'^(Signed-off-by: )(.*)$',
                              re.I | re.M | re.S)
    is_co_author = re.compile(r'^(Co-authored-by: )(.*)$',
                              re.I | re.M | re.S)
    is_gerrit_change_id = re.compile(r'(\s*(change-id: )(.*))$',
                                     re.I | re.M | re.S)
    is_fixes = re.compile(r'(\s*(Fixes:)(.*))$', re.I | re.M | re.S)
    is_fixes_exact = re.compile(r'^Fixes: [0-9a-f]{12} \(".*"\)$')

    tags_typos = {
        r'^Acked by:': 'Acked-by:',
        r'^Reported at:': 'Reported-at:',
        r'^Reported by:': 'Reported-by:',
        r'^Requested by:': 'Requested-by:',
        r'^Reviewed by:': 'Reviewed-by:',
        r'^Submitted at:': 'Submitted-at:',
        r'^Suggested by:': 'Suggested-by:',
    }

    reset_counters()

    for line in text.split("\n"):
        if current_file != previous_file:
            previous_file = current_file

        lineno = lineno + 1
        total_line = total_line + 1

        if line == "\f":
            # Form feed
            continue
        if len(line) <= 0:
            continue

        if checking_file:
            parse = PARSE_STATE_CHANGE_BODY

        if parse == PARSE_STATE_DIFF_HEADER:
            match = hunks.match(line)
            if match:
                parse = PARSE_STATE_CHANGE_BODY
                current_file = match.group(2)[2:]
                print_file_name = current_file
            continue
        elif parse == PARSE_STATE_HEADING:
            if seppatch.match(line):
                parse = PARSE_STATE_DIFF_HEADER
                if not skip_signoff_check:

                    # Check that the patch has an author, that the
                    # author is not among the co-authors, and that the
                    # co-authors are unique.
                    if not author:
                        print_error("Patch lacks author.")
                        continue
                    if " via " in author or "@openvswitch.org" in author:
                        print_error("Author should not be mailing list.")
                        continue
                    if author in co_authors:
                        print_error("Author should not be also be co-author.")
                        continue
                    if len(set(co_authors)) != len(co_authors):
                        print_error("Duplicate co-author.")

                    # Check that the author, all co-authors, and the
                    # committer (if any) signed off.
                    if author not in signatures:
                        print_error("Author %s needs to sign off." % author)
                    for ca in co_authors:
                        if ca not in signatures:
                            print_error("Co-author %s needs to sign off." % ca)
                            break
                    if (committer
                        and author != committer
                        and committer not in signatures):
                        print_error("Committer %s needs to sign off."
                                    % committer)

                    # Check for signatures that we do not expect.
                    # This is only a warning because there can be,
                    # rarely, a signature chain.
                    #
                    # If we don't have a known committer, and there is
                    # a single extra sign-off, then do not warn
                    # because that extra sign-off is probably the
                    # committer.
                    extra_sigs = [x for x in signatures
                                  if x not in co_authors
                                  and x != author
                                  and x != committer]
                    if len(extra_sigs) > 1 or (committer and extra_sigs):
                        print_warning("Unexpected sign-offs from developers "
                                      "who are not authors or co-authors or "
                                      "committers: %s"
                                      % ", ".join(extra_sigs))
            elif is_committer.match(line):
                committer = is_committer.match(line).group(2)
            elif is_author.match(line):
                author = is_author.match(line).group(2)
            elif is_signature.match(line):
                m = is_signature.match(line)
                signatures.append(m.group(2))
            elif is_co_author.match(line):
                m = is_co_author.match(line)
                co_authors.append(m.group(2))
            elif (is_gerrit_change_id.match(line) and
                  not skip_gerrit_change_id_check):
                print_error(
                    "Remove Gerrit Change-Id's before submitting upstream.")
                print("%d: %s\n" % (lineno, line))
            elif is_fixes.match(line) and not is_fixes_exact.match(line):
                print_error('"Fixes" tag is malformed.\n'
                            'Use the following format:\n'
                            '  git log -1 '
                            '--pretty=format:"Fixes: %h (\\\"%s\\\")" '
                            '--abbrev=12 COMMIT_REF\n')
                print("%d: %s\n" % (lineno, line))
            elif spellcheck:
                check_spelling(line, False)
            for typo, correct in tags_typos.items():
                m = re.match(typo, line, re.I)
                if m:
                    print_error("%s tag is malformed." % (correct[:-1]))
                    print("%d: %s\n" % (lineno, line))

        elif parse == PARSE_STATE_CHANGE_BODY:
            newfile = hunks.match(line)
            if newfile:
                current_file = newfile.group(2)[2:]
                print_file_name = current_file
                continue
            reset_line_number = hunk_differences.match(line)
            if reset_line_number:
                empty_return_check_state = RETURN_CHECK_INITIAL_STATE
                lineno = int(reset_line_number.group(3))
                if lineno < 0:
                    lineno = -1 * lineno
                lineno -= 1

            if is_subtracted_line(line):
                lineno -= 1
                continue

            cmp_line = added_line(line)

            if not is_added_line(line):
                interim_line_check(current_file, cmp_line, lineno)
                continue

            # Skip files which have /datapath in them, since they are
            # linux or windows coding standards
            if current_file.startswith('datapath'):
                continue
            if current_file.startswith('include/linux'):
                continue
            # "sparse" includes could be copy-pasted from different sources
            # like DPDK or Linux and could contain workarounds not suitable
            # for a common style.
            if current_file.startswith('include/sparse'):
                continue
            if current_file.startswith('utilities/bugtool'):
                continue
            run_checks(current_file, cmp_line, lineno)

    run_file_checks(text)
    if __errors or __warnings:
        return EXIT_FAILURE
    return 0


def usage():
    print("""\
Open vSwitch checkpatch.py
Checks a patch for trivial mistakes.
usage:
%s [options] [PATCH1 [PATCH2 ...] | -f SOURCE1 [SOURCE2 ...] | -1 | -2 | ...]

Input options:
-f|--check-file                Arguments are source files, not patches.
-1, -2, ...                    Check recent commits in this repo.

Check options:
-h|--help                      This help message
-b|--skip-block-whitespace     Skips the if/while/for whitespace tests
-l|--skip-leading-whitespace   Skips the leading whitespace test
-q|--quiet                     Only print error and warning information
-s|--skip-signoff-lines        Tolerate missing Signed-off-by line
-S|--spellcheck                Check C comments and commit-message for possible
                               spelling mistakes
-t|--skip-trailing-whitespace  Skips the trailing whitespace test
   --skip-gerrit-change-id     Skips the gerrit change id test"""
          % sys.argv[0])


def ovs_checkpatch_print_result():
    global quiet, __warnings, __errors, total_line

    if __errors or __warnings:
        print("Lines checked: %d, Warnings: %d, Errors: %d\n" %
              (total_line, __warnings, __errors))
    elif not quiet:
        print("Lines checked: %d, no obvious problems found\n" % (total_line))


def ovs_checkpatch_file(filename):
    try:
        mail = email.message_from_file(open(filename, 'r', encoding='utf8'))
    except:
        print_error("Unable to parse file '%s'. Is it a patch?" % filename)
        return -1

    for part in mail.walk():
        if part.get_content_maintype() == 'multipart':
            continue
    result = ovs_checkpatch_parse(part.get_payload(decode=False), filename,
                                  mail.get('Author', mail['From']),
                                  mail['Commit'])
    ovs_checkpatch_print_result()
    return result


def partition(pred, iterable):
    """Returns [[trues], [falses]], where [trues] is the items in
    'iterable' that satisfy 'pred' and [falses] is all the rest."""
    trues = []
    falses = []
    for item in iterable:
        if pred(item):
            trues.append(item)
        else:
            falses.append(item)
    return trues, falses


if __name__ == '__main__':
    try:
        numeric_options, args = partition(lambda s: re.match('-[0-9]+$', s),
                                          sys.argv[1:])
        n_patches = int(numeric_options[-1][1:]) if numeric_options else 0

        optlist, args = getopt.getopt(args, 'bhlstfSq',
                                      ["check-file",
                                       "help",
                                       "skip-block-whitespace",
                                       "skip-leading-whitespace",
                                       "skip-signoff-lines",
                                       "skip-trailing-whitespace",
                                       "skip-gerrit-change-id",
                                       "spellcheck",
                                       "quiet"])
    except:
        print("Unknown option encountered. Please rerun with -h for help.")
        sys.exit(EXIT_FAILURE)

    for o, a in optlist:
        if o in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif o in ("-b", "--skip-block-whitespace"):
            skip_block_whitespace_check = True
        elif o in ("-l", "--skip-leading-whitespace"):
            skip_leading_whitespace_check = True
        elif o in ("-s", "--skip-signoff-lines"):
            skip_signoff_check = True
        elif o in ("-t", "--skip-trailing-whitespace"):
            skip_trailing_whitespace_check = True
        elif o in ("--skip-gerrit-change-id"):
            skip_gerrit_change_id_check = True
        elif o in ("-f", "--check-file"):
            checking_file = True
        elif o in ("-S", "--spellcheck"):
            if not open_spell_check_dict():
                print("WARNING: The enchant library isn't available.")
                print("         Please install python enchant.")
            else:
                spellcheck = True
        elif o in ("-q", "--quiet"):
            quiet = True
        else:
            print("Unknown option '%s'" % o)
            sys.exit(EXIT_FAILURE)

    if sys.stdout.isatty():
        colors = True

    if n_patches:
        status = 0

        git_log = 'git log --no-color --no-merges --pretty=format:"%H %s" '
        with os.popen(git_log + '-%d' % n_patches, 'r') as f:
            commits = f.read().split("\n")

        for i in reversed(range(0, n_patches)):
            revision, name = commits[i].split(" ", 1)
            f = os.popen('''git format-patch -1 --stdout --pretty=format:"\
Author: %an <%ae>
Commit: %cn <%ce>
Subject: %s

%b" ''' + revision, 'r')
            patch = f.read()
            f.close()

            if not quiet:
                print('== Checking %s ("%s") ==' % (revision[0:12], name))
            result = ovs_checkpatch_parse(patch, revision)
            ovs_checkpatch_print_result()
            if result:
                status = EXIT_FAILURE
        sys.exit(status)

    if not args:
        if sys.stdin.isatty():
            usage()
            sys.exit(EXIT_FAILURE)
        result = ovs_checkpatch_parse(sys.stdin.read(), '-')
        ovs_checkpatch_print_result()
        sys.exit(result)

    status = 0
    for filename in args:
        if not quiet:
            print('== Checking "%s" ==' % filename)
        result = ovs_checkpatch_file(filename)
        if result:
            status = EXIT_FAILURE
    sys.exit(status)
