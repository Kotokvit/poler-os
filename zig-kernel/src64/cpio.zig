// ============================================================================
// POLER-OS CPIO (newc) Archive Parser — x86_64
// ============================================================================

const std = @import("std");

pub const CpioFile = struct {
    name: []const u8,
    data: []const u8,
    mode: u32,
    size: u32,
};

pub const CpioParser = struct {
    archive_data: []const u8,
    offset: usize = 0,

    pub fn init(data: []const u8) CpioParser {
        return CpioParser{
            .archive_data = data,
            .offset = 0,
        };
    }

    pub fn next(self: *CpioParser) ?CpioFile {
        if (self.offset + 110 > self.archive_data.len) return null;

        const header_ptr = self.archive_data[self.offset .. self.offset + 110];
        const magic = header_ptr[0..6];

        if (!std.mem.eql(u8, magic, "070701") and !std.mem.eql(u8, magic, "070702")) {
            return null; // Invalid magic
        }

        const filesize = parseHex(header_ptr[54..62]);
        const namesize = parseHex(header_ptr[94..102]);
        const mode = parseHex(header_ptr[14..22]);

        if (namesize == 0) return null;

        const filename_start = self.offset + 110;
        if (filename_start + namesize > self.archive_data.len) return null;

        const name = self.archive_data[filename_start .. filename_start + namesize - 1]; // exclude null terminator

        if (std.mem.eql(u8, name, "TRAILER!!!")) {
            return null; // End of archive
        }

        const data_start = (filename_start + namesize + 3) & ~@as(usize, 3);
        if (data_start + filesize > self.archive_data.len) return null;

        const data = self.archive_data[data_start .. data_start + filesize];

        // Advance offset to next entry (aligned to 4 bytes)
        self.offset = (data_start + filesize + 3) & ~@as(usize, 3);

        return CpioFile{
            .name = name,
            .data = data,
            .mode = mode,
            .size = filesize,
        };
    }
};

fn parseHex(ascii: []const u8) u32 {
    var val: u32 = 0;
    for (ascii) |c| {
        val <<= 4;
        if (c >= '0' and c <= '9') {
            val += (c - '0');
        } else if (c >= 'a' and c <= 'f') {
            val += (c - 'a' + 10);
        } else if (c >= 'A' and c <= 'F') {
            val += (c - 'A' + 10);
        }
    }
    return val;
}

test "CpioParser parses in-memory cpio archive" {
    const header1 = "07070100000001000081a4000000000000000000000001000000000000000c000000000000000000000000000000000000000900000000";
    const file1 = "test.txt\x00\x00Hello World!";
    const trailer_header = "0707010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b00000000";
    const trailer_name = "TRAILER!!!\x00";
    
    const archive = header1 ++ file1 ++ trailer_header ++ trailer_name;
    
    var parser = CpioParser.init(archive);
    const parsed_file = parser.next() orelse return error.TestFailed;
    
    try std.testing.expectEqualStrings("test.txt", parsed_file.name);
    try std.testing.expectEqualStrings("Hello World!", parsed_file.data);
    try std.testing.expectEqual(@as(u32, 12), parsed_file.size);
    try std.testing.expectEqual(@as(u32, 0x81a4), parsed_file.mode);
    
    try std.testing.expect(parser.next() == null);
}
