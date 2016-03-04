#!/usr/bin/env python

import argparse
import hashlib
import logging
import os
import os.path
import re
import subprocess
import sys
import tempfile

try:
    from shlex import quote as shlex_quote # Python 3
except ImportError:
    from pipes import quote as shlex_quote # Python 2

try:
    import cPickle as pickle # Python 2
except ImportError:
    import pickle # Python 3


# If set, use modification time instead of MD5-sum as check
opt_dirs = ['.']
hasher = hashlib.md5


SYS_CALLS = [
    "execve",
    "open", "access", "openat",
    "stat", "stat64", "lstat",
]


strace_re = re.compile(r"""
  (?: (?P<pid> \d+ ) \s+ ) ?
  (?:
      # Relevant syscalls
      (?P<syscall>""" + "|".join(SYS_CALLS) + r""")
      \(
  |
      # Irrelevant syscalls
      (?: utimensat | statfs | mkdir )
      \(
  |
      # A continuation line
      <
  |
      # Signals
      ---
  |
      # Exit
      \+\+\+
  )
  """, re.VERBOSE)


arg_re = re.compile(r"""
    (?:
        "
        (?P<string>
            (?:
                \\"
            |
                [^"]
            )*
        )
        "
    |
        [^,]+
    )
    (?: , | \) ) \s*
    """, re.VERBOSE)


def set_file_properties_getter(test):
    global get_file_properties
    get_file_properties = test


def add_relevant_dir(d):
    opt_dirs.append(d)


def hashsum(fname):
    if not os.path.isfile(fname):
        return None
    try:
        with open(fname, 'rb') as fh:
            return hasher(fh.read()).digest()
    except PermissionError:
        return None

def modtime(fname):
    try:
        return os.path.stat(fname)
    except:
        return 'bad'


def modtime_hashsum(fname):
    return (modtime(fname), hashsum(fname))


def files_up_to_date(files, get_file_properties):
    for fname, value in files.iteritems():
        if get_file_properties(fname) != value:
            logging.debug("Not up to date: %s", shlex_quote(fname))
            return False
    return True


def is_relevant(fname):
    path1 = os.path.abspath(fname)
    return any(path1.startswith(os.path.abspath(d))
               for d in opt_dirs)


def cmd_to_str(cmd):
    return " ".join(shlex_quote(arg) for arg in cmd)


def parse_strace_line(line):
    match = re.match(strace_re, line)

    if not match:
        logging.warning("Failed to parse this line: %s",
                        line.rstrip("\n"))
        return None

    syscall = match.group("syscall")
    if not syscall:
        return None

    if syscall == "openat":
        arg_number = 2
    else:
        arg_number = 1

    while arg_number > 0:
        arg_number -= 1
        pos = match.end()
        match = arg_re.match(line, pos)
        if not match:
            raise Exception("Failed to parse arguments to syscall", line, pos)

    filename = match.group("string")
    if not filename:
        raise Exception("Failed to parse arguments to syscall: {}".format(line.rstrip("\n")))

    return filename


def generate_deps(cmd, get_file_properties):
    logging.info('Running: %s', cmd_to_str(cmd))

    outfile = os.path.join(tempfile.mkdtemp(), "pipe")
    os.mkfifo(outfile)
    # TODO: Detect solaris and use truss instead and verify parsing of its
    # output format
    trace_command = ['strace',
                     '-f', '-q',
                     '-e', 'trace=' + ','.join(SYS_CALLS),
                     '-o', outfile,
                     '--']
    trace_command.extend(cmd)
    p = subprocess.Popen(trace_command)

    files = {}
    for line in open(outfile):
        filename = parse_strace_line(line)
        if filename:
            fname = os.path.normpath(filename)
            if (fname not in files and os.path.isfile(fname) and
                    is_relevant(fname)):
                files[fname] = get_file_properties(fname)

    status = p.wait()
    os.remove(outfile)

    return (status, files)


def read_deps(fname):
    try:
        with open(fname, 'rb') as fh:
            return pickle.load(fh)
    except:
        return {}


def write_deps(fname, deps):
    with open(fname, 'wb') as fh:
        pickle.dump(deps, fh)


def memoize_with_deps(depsname, deps, cmd):
    files = deps.get(cmd)
    if not files or not files_up_to_date(files, get_file_properties):
        status, files = generate_deps(cmd, get_file_properties)
        if status == 0:
            deps[cmd] = files
        elif cmd in deps:
            del deps[cmd]
        write_deps(depsname, deps)
        return status
    logging.info('Up to date: %s', cmd_to_str(cmd))
    return 0


def memoize(cmd, depsname='.deps'):
    return memoize_with_deps(depsname, read_deps(depsname), cmd)


def main():
    parser = argparse.ArgumentParser(
        description="Record a command's dependencies, skip if they did not change")
    parser.add_argument("command", nargs='+', help='The command to run')
    parser.add_argument("-d", "--relevant-dir", action='append', default=[])
    parser.add_argument("--verbose", action='store_true')
    parser.add_argument("--debug", action='store_true')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--mtime", action='store_true',
        help="Only use mtime to know if a file changed")
    group.add_argument("--hash", action='store_true',
        help="Only use file contents to know if a file changed")

    args = parser.parse_args()

    cmd = tuple(args.command)
    if args.mtime:
        set_file_properties_getter(modtime)
    elif args.hash:
        set_file_properties_getter(hashsum)
    else:
        set_file_properties_getter(modtime_hashsum)

    for relevant_dir in args.relevant_dir:
        add_relevant_dir(relevant_dir)

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.verbose:
        logging.basicConfig(level=logging.INFO)

    return memoize(cmd)


if __name__ == '__main__':
    sys.exit(main())
