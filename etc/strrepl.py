#! /usr/bin/env python
"""
Position-based replacements of substring
useful for applying changes based on overlapped regex iterators"""

from collections import namedtuple

Change = namedtuple('Change', ['start', 'length', 'repl'])

class StringReplace:
	def __init__(self, s = ''):
		self._changes = []
		self._string = s

	def change(self, replacement, start = 0, length = 0):
		''' add a change,
		start refers to the position in the original string and
		not after any replacement has been carried out; however,
		length refers to the replaced part, and
		any part can only be replaced once;
		
		start is checked, length is not but will trigger exception on final()
		'''
		assert start <= len(self._string), "start=%d, must be <= %d" % (start, len(self._string))
		self._changes.append(Change(start, length, replacement))

	def final(self):
		' build resulting string;  object stays almost constant. '
		self._changes.sort(key = lambda c: c.start)
		totlen = len(self._string) + sum([len(c.repl) - c.length for c in self._changes])
		r = bytearray(totlen)
		curr = 0 # position in r
		orig = 0 # position in _string

		for c in self._changes:
			if c.start > orig:
				# this part of _string is kept
				next = curr + c.start - orig
				r[curr: next] = self._string[orig: c.start]
				curr = next
				orig = c.start

			# this part is replaced
			next = curr + len(c.repl)
			r[curr: next] = c.repl
			curr = next
			orig += c.length

		if orig < len(self._string):
			r[curr: totlen] = self._string[orig: len(self._string)]

		assert len(r) == totlen and len(self._string) - orig == totlen - curr, "bad changes " + str(self._changes)
		return str(r.decode())


if __name__ == '__main__':
	import sys
	import pdb
	if (len(sys.argv) > 1):
		sr = StringReplace(sys.argv[1])
		for i in range(2, len(sys.argv), 3):
			sr.change(sys.argv[i], int(sys.argv[i+1]), int(sys.argv[i+2]))

		print sr.final()
