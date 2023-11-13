#! /usr/bin/env python3

# Copyright (c) 2008, 2011, 2017 Nicira, Inc.
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

from ovs_build_helpers import soutil
import sys
import getopt
import os


def parse_include_dirs():
    include_dirs = []
    options, args = getopt.gnu_getopt(sys.argv[1:], 'I:', ['include='])
    for key, value in options:
        if key in ['-I', '--include']:
            include_dirs.append(value.split(','))
        else:
            assert False

    include_dirs.append(['.'])
    return include_dirs, args


def find_include_file(include_info, name):
    for info in include_info:
        if len(info) == 2:
            dir = info[1]
            var = "$(%s)/" % info[0]
        else:
            dir = info[0]
            var = ""

        file = "%s/%s" % (dir, name)
        try:
            os.stat(file)
            return var + name
        except OSError:
            pass
    sys.stderr.write("%s not found in: %s\n" %
                     (name, ' '.join(str(include_info))))
    return None


def sodepends(include_info, filenames, dst):
    ok = True
    print("# Generated automatically -- do not modify!    "
          "-*- buffer-read-only: t -*-")
    for toplevel in sorted(filenames):
        # Skip names that don't end in .in.
        if not toplevel.endswith('.in'):
            continue

        # Open file.
        include_dirs = [info[1] if len(info) == 2 else info[0]
                        for info in include_info]
        fn = soutil.find_file(include_dirs, toplevel)
        if not fn:
            ok = False
            continue
        try:
            outer = open(fn)
        except IOError as e:
            sys.stderr.write("%s: open: %s\n" % (fn, e.strerror))
            ok = False
            continue

        dependencies = []
        while True:
            line = outer.readline()
            if not line:
                break

            name = soutil.extract_include_directive(line)
            if name:
                include_file = find_include_file(include_info, name)
                if include_file:
                    dependencies.append(include_file)
                else:
                    ok = False

        dst.write("\n%s:" % toplevel[:-3])
        for s in [toplevel] + sorted(dependencies):
            dst.write(' \\\n\t%s' % s)
        dst.write('\n')
        for s in [toplevel] + sorted(dependencies):
            dst.write('%s:\n' % s)
    return ok


if __name__ == '__main__':
    include_dirs, args = parse_include_dirs()
    error = not sodepends(include_dirs, args, sys.stdout)
    sys.exit(1 if error else 0)
