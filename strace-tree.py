#!/usr/bin/env python3
# strace-tree - organise "strace -ff" output into a tree of subprocesses
# Copyright 2021  Simon Arlott
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import os
import re
import sys

RE_EXECVE = re.compile(r'\S+ execve\("(?P<exec>[^"]+)", \["(?P<name>[^"]*)"(?P<args>.+)\].+\) = 0')
RE_CLONE = re.compile(r'\S+ (clone|vfork)\(.*\)\s* = (?P<pid>[0-9]+)')

class StraceFile:
	def __init__(self, filename):
		self.filename = filename
		self.pid = int(self.filename.split(".")[1])
		self.named = False
		self.execve = None
		self.name = None
		self.args = None
		self.clones = set()
		with open(self.filename, "r") as f:
			for line in f:
				line = line.strip()
				if match := RE_EXECVE.fullmatch(line):
					if not self.named:
						self.named = True
						self.execve = match["exec"]
						self.name = match["name"]
						self.args = f'"{self.name}"{match["args"]}'
				elif match := RE_CLONE.fullmatch(line):
					self.clones.add(int(match["pid"]))

	@property
	def execve_basename(self):
		if self.execve is None:
			return None
		return os.path.basename(self.execve)

	@property
	def name_basename(self):
		if self.name is None:
			return None
		return os.path.basename(self.name)

def processes(filenames):
	procs = {}
	for filename in filenames:
		sf = StraceFile(filename)
		procs[sf.pid] = sf
	return procs

def tree(procs):
	clones = set()
	inits = {}

	for proc in procs.values():
		clones |= proc.clones
		proc.children = set(filter(None, [procs.get(clone) for clone in proc.clones]))

	for proc in procs.values():
		if not proc.named:
			if proc.pid in clones:
				proc.execve = proc.name = "clone"
			else:
				proc.execve = proc.name = "init"

		if proc.pid not in clones:
			inits[proc.pid] = proc

	return inits

if __name__ == "__main__":
	def _print_proc(proc, indent=0):
		if proc.named:
			print(f"{' ' * indent * 2} {proc.pid} {proc.execve_basename} [{proc.args[0:64]}]")
		else:
			print(f"{' ' * indent * 2} {proc.pid} {proc.name}")
		for child in proc.children:
			_print_proc(child, indent + 1)

	def _ln_tree(path, proc):
		path = os.path.join(path, f"{proc.pid}.{proc.execve_basename}")
		os.makedirs(path, exist_ok=True)
		filename = os.path.join(path, f"strace")
		if not os.path.exists(filename):
			os.link(proc.filename, filename)
		for child in proc.children:
			_ln_tree(path, child)

	for init in tree(processes(sys.argv[1:])).values():
		_print_proc(init)
		_ln_tree("tree", init)
