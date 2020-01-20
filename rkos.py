#!/usr/bin/python
import sys, struct, os

## THIS FILE IS INTELLECTUAL PROPERTY OF B1N4R1 B01.
## REVIEW CONTACT OPTIONS IN THE README.
## THE MIT LICENSE OF THE PROJECT DOES NOT APPLY TO
## THIS FILE UNLESS LICENSED IN SUCH MANNER BY THE
## AUTHOR.

if __name__ == '__main__':
	myint = 4
	real_offset = 48

	if len(sys.argv) != 2:
		print 'Usage: {} Firmware.bin'.format(sys.argv[0])
		sys.exit(1)

	in_file = sys.argv[1]

	fp = open(in_file,'rb')

	fp.seek(32)
	file_magic = fp.read(8)

	if file_magic != "rkosftab":
		print "Firmware Invalid :("
		sys.exit(1)

	os.system('mkdir extracted')

	print "Extracting Firmware Blobs To Folder 'extracted'"

	fp.seek(16)
	le = fp.read(myint)
	tick_offset = struct.unpack('<i',le)[0]

	print tick_offset

	fp.seek(20)
	le = fp.read(myint)
	tick_size = struct.unpack('<i',le)[0]

	print tick_size

	if tick_size != 0:
		out_file = 'ticket'

		dump = 'dd if={} of=extracted/{} skip={} count={} bs=1 >/dev/null 2>&1'.format(in_file,out_file,tick_offset,tick_size)

		os.system(dump)

		print "Ticket Dumped"

	fp.seek(real_offset)
	tag = fp.read(4)

	fp.seek(real_offset+myint)
	le = fp.read(myint)
	tagoff = struct.unpack('<i',le)[0]

	fp.seek(real_offset+(myint*2))
	le = fp.read(myint)
	tagsz = struct.unpack('<i',le)[0]

	ftagoff = tagoff

	while real_offset < ftagoff:
		statement = "Tag:{} Offset:{} Size:{}".format(tag,hex(tagoff),hex(tagsz))

		print statement

		dump = 'dd if={} of=extracted/{} skip={} count={} bs=1 >/dev/null 2>&1'.format(in_file,tag,tagoff,tagsz)

		os.system(dump)

		real_offset = real_offset + 16

		fp.seek(real_offset)
		tag = fp.read(4)

		fp.seek(real_offset+myint)
		le = fp.read(myint)

		tagoff = struct.unpack('<i',le)[0]

		fp.seek(real_offset+(myint*2))
		le = fp.read(myint)
		tagsz = struct.unpack('<i',le)[0]

		if real_offset == ftagoff:
			fp.close()
			break
