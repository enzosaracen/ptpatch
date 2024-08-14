from elf import *
import random

def mangle(path):
    with open(path, "rb") as file:
        bin = file.read()
    bin = mangle_elfheader(bytearray(bin))
    return bin

def mangle_elfheader(data):
    header = Header.from_buffer(bytearray(data))
    segments = list(Segment.from_buffer(data, header.e_phoff + i*sizeof(Segment)) for i in range(header.e_phnum))
    sections = list(Section.from_buffer(data, header.e_shoff + i*sizeof(Section)) for i in range(header.e_shnum))

    
