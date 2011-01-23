#!/usr/bin/python

import os, os.path, sys, string
from random import randrange

tools_base = '/usr/local/ps3dev/ps3tools'
fix_tar = '/usr/local/ps3dev/ps3utils/fix_tar'

r = randrange(10000, 99999)
pup = sys.argv[1]
pup_filename = os.path.basename(pup)
pup_base = os.path.dirname(pup)
pup_dir = '%s_%d' % (pup, r)
patched_lv1 = open(sys.argv[2], 'rb').read()
patched_lv2 = open(sys.argv[3], 'rb').read()
out_pup = sys.argv[4]

# extract CORE_OS_PACKAGE.pkg
os.system('"%s/pupunpack" "%s" "%s"' % (tools_base, pup, pup_dir))
os.system('mkdir "%s/update_files"' % pup_dir)
os.system('tar -xvf "%s/update_files.tar" -C "%s/update_files"' % (pup_dir, pup_dir))
os.system('"%s/unpkg" "%s/update_files/CORE_OS_PACKAGE.pkg" "%s/update_files/cos"' % (tools_base, pup_dir, pup_dir))
os.system('"%s/cosunpkg" "%s/update_files/cos/content" "%s/update_files/cos/files"' % (tools_base, pup_dir, pup_dir))

content_h = open('%s/update_files/cos/content' % pup_dir, 'rb')
content = content_h.read()
content_h.close()

# write new lv1.self
original_lv1 = open('%s/update_files/cos/files/lv1.self' % pup_dir, 'rb').read()
lv1_offset = string.find(content, original_lv1)
print "lv1 is at %s in content" % hex(lv1_offset)
if len(original_lv1) != len(patched_lv1):
	print "patched lv1 must be same size as original"
	sys.exit(0)
content = content[:lv1_offset] + patched_lv1 + content[lv1_offset + len(patched_lv1):]

# write new lv2_kernel.self
original_lv2 = open('%s/update_files/cos/files/lv2_kernel.self' % pup_dir, 'rb').read()
lv2_offset = string.find(content, original_lv2)
print "lv2 is at %s in content" % hex(lv2_offset)
if len(original_lv2) != len(patched_lv2):
	print "patched lv2 must be same size as original"
	sys.exit(0)
content = content[:lv2_offset] + patched_lv2 + content[lv2_offset + len(patched_lv2):]
	
new_content = open('%s/update_files/cos/content' % pup_dir, 'wb')
new_content.write(content)
new_content.close()

# repackage CORE_OS_PACKAGE.pkg
os.system('rm -rf "%s/update_files/cos/files"' % pup_dir)
os.system('"%s/pkg" retail "%s/update_files/cos" "%s/update_files/CORE_OS_PACKAGE.pkg"' % (tools_base, pup_dir, pup_dir))
os.system('rm -rf "%s/update_files/cos"' % pup_dir)

# repackage update_files.tar
os.system('rm "%s/update_files.tar"' % pup_dir)
cwd = os.getcwd()
os.chdir('%s/update_files' % pup_dir)
os.system('tar --format ustar -cvf "%s/update_files.tar" *' % pup_dir)
os.chdir(cwd)
os.system('rm -rf "%s/update_files"' % pup_dir)
os.system('"%s" "%s/update_files.tar"' % (fix_tar, pup_dir))

# repackage pup
os.system('puppack "%s" "%s"' % (out_pup, pup_dir))
os.system('rm -rf "%s"' % pup_dir)