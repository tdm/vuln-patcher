#!/usr/bin/python

import os
import sys
import requests
import getopt
from xml.etree import ElementTree
import subprocess

def dequote(s):
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s

def cmd_run(args, stdin=None):
    child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not stdin is None:
        child.stdin.write(stdin)
    (out, err) = child.communicate()
    rc = child.returncode
    return (rc, out.rstrip('\n').split('\n'), err.rstrip('\n').split('\n'))

class Version:
    def __init__(self, ver):
        self._segments = []
        if len(ver) > 0:
            self._segments = ver.split('.')

    def __str__(self):
        return '.'.join(self._segments)

    def __hash__(self):
        return hash(self.__str__())

    def empty(self):
        return len(self._segments) == 0

    def cmp(self, other):
        seg = 0
        while seg < len(self._segments):
            if seg >= len(other._segments):
                return 1
            s1 = int(self._segments[seg])
            s2 = int(other._segments[seg])
            if s1 != s2:
                return s1 - s2
            seg += 1
        if seg < len(other._segments):
            return -1
        return 0

    def __lt__(self, other):
        return self.cmp(other) < 0
    def __le__(self, other):
        return self.cmp(other) <= 0
    def __eq__(self, other):
        return self.cmp(other) == 0
    def __ne__(self, other):
        return self.cmp(other) != 0
    def __gt__(self, other):
        return self.cmp(other) > 0
    def __ge__(self, other):
        return self.cmp(other) >= 0

    def in_range(self, vmin, vmax):
        if not vmin.empty():
            if self < vmin:
                return False
        if not vmax.empty():
            if self > vmax:
                return False
        return True

class Patch:
    def __init__(self, text):
        self._text = text
        self._files = []
        for line in text.split('\n'):
            fields = line.split(' ', 1)
            if len(fields) < 2:
                continue
            if fields[0] == 'From':
                self._sha = fields[1]
            if fields[0] == 'From:':
                self._author = fields[1]
            if fields[0] == 'Date:':
                self._date = fields[1]
            if fields[0] == 'Subject:':
                self._subject = fields[1]
            if fields[0] == 'diff':
                fields = line.split(' ')
                self._files.append(fields[2][2:])

    @classmethod
    def from_url(cls, url):
        rs = requests.Session()
        r = rs.get(url)
        r.raise_for_status()
        return cls(r.content)

    @classmethod
    def from_text(cls, text):
        return cls(text)

    def sha(self):
        return self._sha

    def subject(self):
        return self._subject

    def files(self):
        return self._files

    def can_apply(self):
        argv = ['patch', '-p1', '--force', '--dry-run']
        (rc, out, err) = cmd_run(argv, self._text)
        return (rc == 0)

    def can_reverse(self):
        argv = ['patch', '-p1', '--force', '--dry-run', '--reverse']
        (rc, out, err) = cmd_run(argv, self._text)
        return (rc == 0)

    def apply(self):
        argv = ['patch', '-p1', '--force', '--no-backup-if-mismatch']
        (rc, out, err) = cmd_run(argv, self._text)
        if rc != 0:
            raise RuntimeError("Patch failed to apply")

    def reverse(self):
        argv = ['patch', '-p1', '--force', '--reverse']
        (rc, out, err) = cmd_run(argv, self._text)
        if rc != 0:
            raise RuntimeError("Patch failed to reverse")

    def in_git_history(self):
        found = 0
        for f in self._files:
            argv = ['git', 'log', '--oneline', f]
            (rc, out, err) = cmd_run(argv)
            if rc != 0:
                continue
            for line in out:
                fields = line.split(' ', 1)
                if fields[1] == self._subject:
                    found += 1
                    break
        return (found == len(self._files))

    def git_am(self):
        argv = ['git', 'am']
        (rc, out, err) = cmd_run(argv, patch._text)
        if rc != 0:
            raise RuntimeError("Patch failed to merge")

def get_kernel_version():
    f = open("Makefile")
    for line in f:
        fields = line.split('=')
        if len(fields) != 2:
            continue
        key = fields[0].strip()
        val = fields[1].strip()
        if key == 'VERSION':
            v_major = int(val)
        if key == 'PATCHLEVEL':
            v_minor = int(val)
    f.close()
    return Version("%d.%d" % (v_major, v_minor))

def get_vuln_list():
    vuln_list = []
    rs = requests.Session()
    print "Fetching vuln list"
    vl_r = rs.get("http://code.nwwn.com/vuln/vuln_list.php?format=xml&off=0&len=1000")
    vl_r.raise_for_status()
    vl_root = ElementTree.fromstring(vl_r.text)
    for vl_elem in vl_root:
        vuln = dict()
        id = dequote(vl_elem.attrib['id'])
        v_r = rs.get("http://code.nwwn.com/vuln/vuln_detail.php?format=xml&id=%s" % (id))
        v_root = ElementTree.fromstring(v_r.text)
        vuln['name'] = dequote(v_root.find('name').text)
        vuln['version_min'] = Version(dequote(v_root.find('version_min').text))
        vuln['version_max'] = Version(dequote(v_root.find('version_max').text))
        vuln['comments'] = dequote(v_root.find('comments').text)

        vuln['patches'] = dict()
        p_root = v_root.find('patch_list')
        for p in p_root.findall('patch'):
            ver = Version(dequote(p.attrib['version']))
            url = dequote(p.text)
            vuln['patches'][ver] = url
        print "Vuln id=%s name=%s v_min=%s v_max=%s has %d patches" % (id,
                vuln['name'], vuln['version_min'], vuln['version_max'],
                len(vuln['patches']))
        vuln_list.append(vuln)
    return vuln_list

def find_best_patch_url(kver, vuln):
    patches = vuln['patches']
    if len(patches) == 0:
        return ''
    if kver in patches:
        return patches[kver]
    for v in patches:
        return patches[v]

cfg = dict()
cfg['dry-run'] = False

optargs, argv = getopt.getopt(sys.argv[1:], 'n', ['dry-run'])
for k, v in optargs:
    if k in ('-n', '--dry-run'):
        cfg['dry-run'] = True

kver = get_kernel_version()
vuln_list = get_vuln_list()

for vuln in vuln_list:
    name = vuln['name']
    vmin = vuln['version_min']
    vmax = vuln['version_max']
    if not kver.in_range(vmin, vmax):
        print "Vuln %s does not apply: %s not in [%s,%s]" % (name, kver, vmin, vmax)
        continue
    patch_url = find_best_patch_url(kver, vuln)
    if not patch_url:
        print "Vuln %s has no patches" % (name)
        continue
    patch = Patch.from_url(patch_url)
    if patch.can_reverse():
        print "Vuln %s is patched" % (name)
        continue
    if patch.in_git_history():
        print "Vuln %s in git history" % (name)
        continue
    if cfg['dry-run']:
        if patch.can_apply():
            print "Vuln %s can apply" % (name)
        else:
            print "Vuln %s cannot apply" % (name)
        continue
    if patch.can_apply():
        try:
            patch.git_am()
            print "Vuln %s patched successfully" % (name)
        except RuntimeError:
            print "Vuln %s failed to merge, patching manually..." % (name)
            patch.apply()
            reply = raw_input("  Please verify and press enter to continue...")
            argv = ['git', 'add']
            argv.extend(patch.files())
            (rc, out, err) = cmd_run(argv)
            if rc != 0:
                raise RuntimeError("Failed to git add files")
            argv = ['git', 'am', '--continue']
            (rc, out, err) = cmd_run(argv)
            if rc != 0:
                raise RuntimeError("Failed to continue merge")
    else:
        print "Vuln %s cannot apply" % (name)
        reply = raw_input("  Please apply and press enter to continue...")
