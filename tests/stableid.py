#!/usr/bin/env python

import sys
import pickle

# DDlog has difficulty allocating ids in a predictable manner.  This program
# takes an integer on stdin and maps it to a stable id.  By default, stable
# ids are allocated in an incrementing order, starting at 1.  The only
# required command line argument is a group name to create separate
# allocation groupings.  The following optional arguments are available:
#
#   * "--strict": An attempt is made to use the input as the stable id.  If
#     the input already has a different assigned id or the requested id is
#     already in use, an error message is printed and the program exits with
#     exit code 1.
#
#   * "--del": Delete the mapping provided on stdin.
#
#   * "--dump": Dump the current mappings.

def allocate_id(ids, id, strict):
    if strict:
        if id in ids and ids[id] == id:
            return
        elif id not in ids.values():
            ids[id] = id;
        else:
            sys.stderr.write("Couldn't assign requested id\n")
            sys.exit(1)

    if id in ids:
        return

    # Allocate the lowest available id
    for i in range(1, 1000):
        if str(i) not in ids.values():
            ids[id] = str(i)
            return

    sys.stderr.write("Couldn't allocate stable id\n")
    sys.exit(1)

if __name__ == '__main__':
    strict = False
    delete = False
    dump = False

    if len(sys.argv) == 3 and sys.argv[1] == "--strict":
        strict = True
    elif len(sys.argv) == 3 and sys.argv[1] == "--del":
        delete = True
    elif len(sys.argv) == 3 and sys.argv[1] == "--dump":
        dump = True
    elif len(sys.argv) != 2:
        sys.stderr.write("%s [--strict|--del|--dump] group\n" % sys.argv[0])
        sys.exit(1)

    filename = "stableid-" + sys.argv[-1]

    try:
        f = open(filename, 'rb')
        ids = pickle.load(f)
        f.close()
    except IOError:
        ids = {}

    if dump:
        print ids
        sys.exit(0)

    id = sys.stdin.readline().rstrip()
    if not id:
        sys.exit(0)

    if delete:
        if id in ids:
            del ids[id]
    else:
        allocate_id(ids, id, strict)
        print ids[id]

    f = open(filename, 'wb')
    pickle.dump(ids, f, pickle.HIGHEST_PROTOCOL)
    f.close()
