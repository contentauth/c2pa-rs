"""Generates sample1-data-descriptor.zip. See README.md."""

import io
import struct
import zipfile
from pathlib import Path


class NonSeekable(io.RawIOBase):
    """Write-only stream that can't seek, so zipfile writes data descriptors."""

    def __init__(self):
        self.buffer = bytearray()

    def writable(self):
        return True

    def write(self, data):
        self.buffer += data
        return len(data)


ENTRIES = [
    ("first.txt", b"Content Credentials " * 200),
    ("dir/second.txt", b"second entry"),
]

stream = NonSeekable()
with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for name, contents in ENTRIES:
        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, contents)
data = bytes(stream.buffer)

# Every local header has the data descriptor flag set and the deflate method.
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    for info in archive.infolist():
        offset = info.header_offset
        assert data[offset : offset + 4] == b"PK\x03\x04"
        flags, method = struct.unpack_from("<HH", data, offset + 6)
        assert flags & 0x08 and method == zipfile.ZIP_DEFLATED, info.filename
    assert [archive.read(n) for n, _ in ENTRIES] == [c for _, c in ENTRIES]

Path(__file__).with_name("sample1-data-descriptor.zip").write_bytes(data)
