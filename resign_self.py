#!/usr/bin/python

# put erk, riv, priv, p, a, b, N, Gx, Gy here

import sys, struct, hashlib, hmac, ecdsa, ellipticcurve, zlib
from Crypto.Cipher import AES
from random import SystemRandom
randrange = SystemRandom().randrange

def error(reason):
	print reason
	sys.exit(1)
	
def aes128ctr(buf, key, iv):
	aes = AES.new(key, AES.MODE_ECB)
	out = ''
	for i in range(len(buf)):
		if (i & 0xf) == 0:
			ctr = aes.encrypt(iv)
			tmp = struct.unpack('>Q', iv[8:])[0] + 1
			iv = iv[:8] + struct.pack('>Q', tmp)
			if tmp == 0:
				iv = struct.pack('>I', iv + 1)
		out += chr(ord(buf[i]) ^ ord(ctr[i & 0x0f]))
	return out, iv

def bit_length(v):
	length = 0
	while v:
		v >>= 1
		length += 1
	return length
	
def pack_int(int_val, num_words=4, word_size=32):
    max_int = 2 ** (word_size*num_words) - 1
    max_word_size = 2 ** word_size - 1
    if not 0 <= int_val <= max_int:
        raise IndexError('integer %r is out of bounds!' % hex(int_val))
    words = []
    for _ in range(num_words):
        word = int_val & max_word_size
        words.append(int(word))
        int_val >>= word_size
    words.reverse()
    return words

def pack(int_val, width=128, word_size=32):
    STRUCT_FMT = {8: 'B', 16: 'H', 32: 'I'}
    num_words = width / word_size
    words = pack_int(int_val, num_words, word_size)
    try:
        fmt = '>%d%s' % (num_words, STRUCT_FMT[word_size])
    except KeyError:
        raise ValueError('unsupported word size: %d!' % word_size)
    return struct.pack(fmt, *words)

def unpack(b):
	v = 0
	for i in range(0, len(b), 1):
		v |= ord(b[i]) * (0x10 ** ((len(b) - i) * 2))
	return v / 0x100
	
def section_flags(offset):
	global f, sec_offset, elf_offset
	e_phnum = struct.unpack('>H', f[elf_offset + 0x38:elf_offset + 0x3A])[0]
	for i in range(e_phnum):
		cur_offset = struct.unpack('>Q', f[sec_offset + i*0x20 + 0x00:sec_offset + i*0x20 + 0x08])[0]
		compressed = struct.unpack('>I', f[sec_offset + i*0x20 + 0x10:sec_offset + i*0x20 + 0x14])[0]
		encrypted = struct.unpack('>I', f[sec_offset + i*0x20 + 0x1C:sec_offset + i*0x20 + 0x20])[0]
		if cur_offset == offset:
			return encrypted, compressed		
	return False, False
	
def write_section(offset, size, key, iv, encrypt=True, deflate=True):
	global f
	new_seg = open(new_seg_filename, 'rb').read()
	
	if deflate:
		print "Deflating new section"
		new_seg = zlib.compress(new_seg)

	if size != len(new_seg) and deflate:
		error("Section size mismatch. Deflated length is %d bytes, required length is %d bytes." % (len(new_seg), size))
	elif size != len(new_seg):
		error("Section size mismatch. Your section must be the same size as the original.")
	
	if encrypt:
		print "Encrypting new section"
		new_seg, crap = aes128ctr(new_seg, key, iv)
		
	print "Embedding new section into self"
	f = f[:offset] + new_seg + f[offset + size:]

if len(sys.argv) == 5:
	self_filename = sys.argv[1]
	new_seg_filename = sys.argv[2]
	target_section = int(sys.argv[3])
	out_filename = sys.argv[4]
elif len(sys.argv) == 3:
	self_filename = sys.argv[1]
	new_seg_filename = None
	target_section = None
	out_filename = sys.argv[2]
else:
	print "Just sign: resign_self.py <self> <output>\nOverwrite section and sign: resign_self.py <self> <new section> <section id> <output>"
	sys.exit(0)
	
globals()['f'] = open(sys.argv[1], 'rb').read()
globals()['sec_offset'] = struct.unpack('>Q', f[0x48:0x50])[0]
globals()['elf_offset'] = struct.unpack('>Q', f[0x30:0x38])[0]
meta_offset = struct.unpack('>I', f[0xc:0x10])[0]
header_len = struct.unpack('>Q', f[0x10:0x18])[0]
meta_len = header_len - meta_offset

# decrypt metadata header
print "Decrypting metadata"
aes = AES.new(erk, AES.MODE_CBC, riv)
meta_keys_enc = f[meta_offset + 0x20:meta_offset + 0x60]
meta_keys = aes.decrypt(meta_keys_enc)

# check decryption worked
success = 1
for j in range(0x10, 0x20):
	if meta_keys[j] != '\x00':
		success = 0
for j in range(0x30, 0x40):
	if meta_keys[j] != '\x00':
		success = 0	
if success == 0:
	error("Failed to decrypt metadata, wrong erk/riv")

# decrypt rest of metadata	
meta_key = meta_keys[0x0:0x10]
meta_iv = meta_keys[0x20:0x30]
meta_header_enc = f[meta_offset + 0x60:meta_offset + 0x80]
meta_header, meta_iv = aes128ctr(meta_header_enc, meta_key, meta_iv)
meta, crap = aes128ctr(f[meta_offset + 0x80:meta_offset + meta_len], meta_key, meta_iv)

print "Parsing metadata"
# get number of encrypted sections and available keys
section_count = struct.unpack('>I', meta_header[0xC:0x10])[0]
key_count = struct.unpack('>I', meta_header[0x10:0x14])[0]
print section_count, "sections,", key_count, "keys"

# get key list
keys = []
for i in range(key_count):
	k = (0x30 * section_count) + (0x10 * i)
	keys.append(meta[k:k + 0x10])

# for each section in metadata, recalculate sha1 and replace
for i in range(section_count):
	s = (0x30 * i)
	offset = struct.unpack('>Q', meta[s:s + 0x08])[0]
	size = struct.unpack('>Q', meta[s + 0x08:s + 0x10])[0]
	key_id = struct.unpack('>I', meta[s + 0x24:s + 0x28])[0]
	iv_id = struct.unpack('>I', meta[s + 0x28:s + 0x2C])[0]
	sha_key_id = struct.unpack('>I', meta[s + 0x1C:s + 0x20])[0]
	hmac_key = keys[sha_key_id + 2] + keys[sha_key_id + 3] + keys[sha_key_id + 4] + keys[sha_key_id + 5]
	
	is_encrypted, is_compressed = section_flags(offset)
	if i == target_section:
		write_section(offset, size, keys[key_id], keys[iv_id], is_encrypted, is_compressed)
	
	print "Checking section at 0x%016x" % offset
	encrypted = f[offset:offset + size]
	if is_encrypted and key_id != 0xffffffff and iv_id != 0xffffffff:
		key = keys[key_id]
		iv = keys[iv_id]
		decrypted, crap = aes128ctr(encrypted, key, iv)
	else:
		print "Section not encrypted"
		continue # not encrypted
	
	# get the correct hash and fix the one in metadata if necessary
	correct_sha = hmac.new(hmac_key, decrypted, hashlib.sha1).digest()
	if correct_sha != keys[sha_key_id] + keys[sha_key_id + 1][:0x4]:
		print "Corrected invalid hash"
		k1 = (0x30 * section_count) + (0x10 * sha_key_id)
		k2 = (0x30 * section_count) + (0x10 * (sha_key_id + 1))
		meta = meta[:k1] + correct_sha[:0x10] + meta[k1 + 0x10:]
		meta = meta[:k2] + correct_sha[0x10:] + ('\x00' * 0xC) + meta[k2 + 0x10:]
	else:
		print "Section already has correct hash"
	
# reinsert decrypted metadata into file
f = f[:meta_offset + 0x20] + meta_keys + meta_header + meta + f[meta_offset + meta_len:]

# self signature is now invalid, so we need to fix it
print "Fixing signature"
sig_len = struct.unpack('>Q', meta_header[0x0:0x8])[0]
hash = int(hashlib.sha1(f[:sig_len]).hexdigest(), 16)
curve = ellipticcurve.CurveFp(p, a, b)
g = ellipticcurve.Point(curve, Gx, Gy, N)
pubkey = ecdsa.Public_key(g, g * priv)
privkey = ecdsa.Private_key(pubkey, priv)
sig = privkey.sign(hash, randrange(1, N))
meta = meta[:sig_len - meta_offset - 0x80] + '\x00' + pack(sig.r, 160) + '\x00' + pack(sig.s, 160) + meta[sig_len - meta_offset - 0x80 + 42:]

# reencrypt metadata and reinsert into self
print "Re-encrypting and inserting metadata"
meta, crap = aes128ctr(meta, meta_key, meta_iv)
f = f[:meta_offset + 0x20] + meta_keys_enc + meta_header_enc + meta + f[meta_offset + meta_len:]

# dump output to file
out = open(out_filename, 'wb')
out.write(f)
out.close()
print "Dumped patched self into %s" % out_filename