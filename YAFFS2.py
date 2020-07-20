#!/usr/bin/env python

from struct import pack, unpack
from pathlib import Path
import array


class Yaffs2Chunk(object):

    def __init__(self):
        self.hdr = Yaffs2Hdr()
        self.oob = Yaffs2OOB()

    def pack(self):
        chunk_data = self.hdr.pack()
        chunk_data = chunk_data.ljust(0x800, b'\xff')
        chunk_data += self.oob.pack()
        chunk_data = chunk_data.ljust(0x840, b'\xff')
        return chunk_data


class Yaffs2PadChunk(object):

    def pack(self):
        return b"\xff" * 0x840


class Yaffs2DirHeaderChunk(Yaffs2Chunk):

    def __init__(self, name, mode, uid, gid,
                 parent, seq_number, obj_id):
        Yaffs2Chunk.__init__(self)

        self.hdr.type = 3
        self.hdr.name[0:len(name)] = name

        self.hdr.yst_mode = mode
        self.hdr.yst_uid = uid
        self.hdr.yst_gid = gid

        self.hdr.parent_obj_id = parent
        self.oob.obj_id = obj_id
        self.oob.seq_number = seq_number


class Yaffs2SymHeaderChunk(Yaffs2Chunk):

    def __init__(self, name, target,
                 mode, uid, gid,
                 parent, seq_number, obj_id):
        Yaffs2Chunk.__init__(self)

        self.hdr.type = 2
        self.hdr.name[0:len(name)] = name

        self.hdr.alias[0:len(target)] = target

        self.hdr.yst_mode = mode
        self.hdr.yst_uid = uid
        self.hdr.yst_gid = gid

        self.hdr.parent_obj_id = parent
        self.oob.obj_id = obj_id
        self.oob.seq_number = seq_number


class Yaffs2FileHeaderChunk(Yaffs2Chunk):

    def __init__(self, name,
                 mode, uid, gid,
                 parent,
                 filesize, seq_number,
                 obj_id):
        Yaffs2Chunk.__init__(self)

        self.hdr.type = 1
        self.hdr.name[0:len(name)] = name

        self.hdr.yst_mode = mode
        self.hdr.yst_uid = uid
        self.hdr.yst_gid = gid

        self.hdr.parent_obj_id = parent
        self.oob.obj_id = obj_id
        self.oob.seq_number = seq_number
        self.hdr.file_size_low = filesize & 0xffffffff
        self.hdr.file_size_high = filesize >> 32


class Yaffs2DataChunk(object):

    def __init__(self, content, chunk_id,
                 seq_number, obj_id):
        self.content = content

        self.oob = Yaffs2OOB()
        self.oob.obj_id = obj_id
        self.oob.seq_number = seq_number
        self.oob.chunk_id = chunk_id
        self.oob.n_bytes = len(content)

    def pack(self):
        chunk_data = self.content.ljust(0x800, b'\xff')
        chunk_data += self.oob.pack()
        chunk_data = chunk_data.ljust(0x840, b'\xff')
        return chunk_data


class Yaffs2Hdr(object):

    def __init__(self):
        self.type = 0

        self.parent_obj_id = 0
        self.name = bytearray(256)

        self.yst_mode = 0

        self.yst_uid = 0
        self.yst_gid = 0
        self.yst_atime = 0
        self.yst_mtime = 0
        self.yst_ctime = 0

        self.file_size_low = 0

        self.equiv_id = 0

        self.alias = bytearray(159)

        self.yst_rdev = 0

        self.win_ctime = array.array("I", [0, 0])
        self.win_atime = array.array("I", [0, 0])
        self.win_mtime = array.array("I", [0, 0])

        self.inband_shadowed_obj_id = 0
        self.inband_is_shrink = 0

        self.file_size_high = 0
        self.reserved = 0
        self.shadows_obj = 0

        self.is_shrink = 0

    def pack(self):
        hdr = pack("IIH", self.type, self.parent_obj_id, 0xffff)
        hdr += self.name.ljust(256, b'\x00')
        hdr += b"\xff" * 2
        hdr += pack("IIIIII", self.yst_mode, self.yst_uid, self.yst_gid,
                    self.yst_atime, self.yst_mtime, self.yst_ctime)
        hdr += pack("I", self.file_size_low)
        hdr += pack("I", self.equiv_id)
        hdr += self.alias.ljust(159, b'\x00')
        hdr += pack("I", self.yst_rdev)
        hdr += self.win_ctime.tobytes()
        hdr += self.win_atime.tobytes()
        hdr += self.win_mtime.tobytes()
        hdr += pack("II", self.inband_shadowed_obj_id, self.inband_is_shrink)
        hdr += pack("III", self.file_size_high,
                    self.reserved, self.shadows_obj)
        hdr += pack("I", self.is_shrink)

        return hdr


class Yaffs2OOB(object):

    def __init__(self):
        self.seq_number = 0
        self.obj_id = 0
        self.chunk_id = 0
        self.n_bytes = 0

    def pack(self):
        oob = b"\xff" * 2 + pack("IIII", self.seq_number, self.obj_id,
                                 self.chunk_id, self.n_bytes)
        oob = oob.ljust(0x40, b'\xff')
        return oob


class Yaffs2Partition(object):

    def __init__(self):
        self.current_seq_number = 0x00001000
        self.current_chunk_index = 0
        self.current_obj_id = 258
        self.obj = {}
        self.chunks = []

        self.obj[Path(".")] = 1

    def add_dir(self, dirname, mode=0, uid=0, gid=0):
        path = Path(dirname)

        parent_id = self.get_id(str(path.parent))

        chunk = Yaffs2DirHeaderChunk(path.name.encode(), mode, uid, gid,
                                     parent_id,
                                     seq_number=self.current_seq_number,
                                     obj_id=self.current_obj_id)

        self.obj[path] = self.current_obj_id
        self.current_obj_id += 1

        self.add_chunk(chunk)

    def add_sym(self, filename, target, mode=0, uid=0, gid=0):
        path = Path(filename)

        parent_id = self.get_id(str(path.parent))

        chunk = Yaffs2SymHeaderChunk(path.name.encode(), target.encode(),
                                     mode, uid, gid,
                                     parent_id,
                                     seq_number=self.current_seq_number,
                                     obj_id=self.current_obj_id)

        self.obj[path] = self.current_obj_id
        self.current_obj_id += 1

        self.add_chunk(chunk)

    def add_file(self, filename, content, mode=0, uid=0, gid=0):
        path = Path(filename)

        parent_id = self.get_id(str(path.parent))

        chunk = Yaffs2FileHeaderChunk(path.name.encode(), mode, uid, gid,
                                      parent_id,
                                      filesize=len(content),
                                      seq_number=self.current_seq_number,
                                      obj_id=self.current_obj_id)
        self.add_chunk(chunk)

        self.obj[path] = self.current_obj_id

        for offset in range(0, len(content), 0x800):
            data = content[offset:offset+0x800]
            chunk = Yaffs2DataChunk(data,
                                    chunk_id=1+offset//0x800,
                                    seq_number=self.current_seq_number,
                                    obj_id=self.current_obj_id)
            self.add_chunk(chunk)

        self.current_obj_id += 1

    def get_id(self, object_path):
        object_path = Path(object_path)
        return self.obj[object_path]

    def add_chunk(self, chunk):
        self.chunks.append(chunk)
        self.current_chunk_index += 1
        if self.current_chunk_index == 64:
            self.current_chunk_index = 0
            self.current_seq_number += 1

    def finish_block(self):
        while self.current_chunk_index != 0:
            self.add_chunk(Yaffs2PadChunk())

    def save(self, f):
        for chunk in self.chunks:
            f.write(chunk.pack())
