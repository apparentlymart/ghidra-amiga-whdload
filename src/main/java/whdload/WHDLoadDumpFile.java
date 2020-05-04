package whdload;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class WHDLoadDumpFile {
    public MemoryRegion baseMem;
    public MemoryRegion expMem;
    public MemoryRegion resLoad;
    public MemoryRegion helper;
    public MemoryRegion customChips;
    public String helperName;

    public static boolean isDumpFile(BinaryReader reader) {
        try {
            String form = reader.readNextAsciiString(4);
            if (!form.equals("FORM")) {
                return false;
            }
            reader.readNextAsciiString(4); // skip the length, for now
            String whdd = reader.readNextAsciiString(4);
            if (!whdd.equals("WHDD")) {
                return false;
            }
            return true;
        } catch (IOException ex) {
            return false;
        }
    }

    public WHDLoadDumpFile(BinaryReader reader, TaskMonitor monitor, MessageLog log)
            throws IOException, CancelledException {
        reader.setLittleEndian(false); // IFF files use big-endian numbers
        String form = reader.readNextAsciiString(4);
        if (!form.equals("FORM")) {
            throw new IOException("missing FORM marker: not IFF?");
        }
        reader.readNextAsciiString(4); // skip the length
        String whdd = reader.readNextAsciiString(4);
        if (!whdd.equals("WHDD")) {
            throw new IOException("incorrect IFF FORM type: want WHDD, but got " + whdd);
        }

        long length = reader.length();
        monitor.setMaximum(length);
        long nextChunkStart = reader.getPointerIndex();
        boolean seenHead = false;
        while (true) {
            monitor.checkCanceled();
            monitor.setProgress(nextChunkStart);
            if (nextChunkStart >= length) {
                break;
            }
            reader.setPointerIndex(nextChunkStart);
            String chunkType = reader.readNextAsciiString(4);
            int size = reader.readNextInt();
            chunkType = chunkType.trim();
            monitor.setMessage(String.format("%s chunk", chunkType));
            log.appendMsg(String.format("%s chunk of length %d at 0x%08x", chunkType, size, nextChunkStart));
            // Set up the pointer to the next chunk for our next iteration,
            // so we'll start in the right place even if our processing on
            // this iteration doesn't land exactly at the end of the current
            // chunk.
            nextChunkStart = nextChunkStart + size + 8;
            if ((nextChunkStart % 2) != 0) {
                // Chunks always start at even offsets.
                nextChunkStart++;
            }

            switch (chunkType) {
                case "HEAD":
                    seenHead = true;
                    long bodyStart = reader.getPointerIndex();
                    long baseMemSize = reader.readUnsignedInt(bodyStart);
                    if (baseMemSize < 256) {
                        // Need at least enough space for the CPU vector table.
                        baseMemSize = 256;
                    }
                    this.baseMem = new MemoryRegion(0, baseMemSize);

                    long expMemStart = reader.readUnsignedInt(bodyStart + 0x118);
                    long expMemLength = reader.readUnsignedInt(bodyStart + 0x120);
                    if (expMemLength != 0) {
                        this.expMem = new MemoryRegion(expMemStart, expMemLength);
                    }

                    long resLoadStart = reader.readUnsignedInt(bodyStart + 0x124);
                    long resLoadLength = reader.readUnsignedInt(bodyStart + 0x12c);
                    if (resLoadLength != 0) {
                        this.resLoad = new MemoryRegion(resLoadStart, resLoadLength);
                    }

                    long helperStart = reader.readUnsignedInt(bodyStart + 0x130);
                    long helperLength = reader.readUnsignedInt(bodyStart + 0x138);
                    if (helperLength != 0) {
                        this.helper = new MemoryRegion(helperStart, helperLength);
                    }

                    this.helperName = reader.readTerminatedString(bodyStart + 0x13C, "\0");

                    break;
                case "MEM":
                    // The whole of this block is the content of the baseMem
                    // memory region.
                    if (this.baseMem != null) {
                        log.appendMsg(String.format("Reading %d bytes of base memory image", size));
                        this.baseMem.content = reader.readNextByteArray(size);
                    } else {
                        log.appendMsg("Ignoring base memory image because we have no memory region for it");
                    }
                    break;
                case "EMEM":
                    // The whole of this block is the content of the expMem
                    // memory region.
                    if (this.expMem != null) {
                        log.appendMsg(String.format("Reading %d bytes of expansion memory image", size));
                        this.expMem.content = reader.readNextByteArray(size);
                    } else {
                        log.appendMsg("Ignoring expansion memory image because we have no memory region for it");
                    }
                    break;
                case "SLAV":
                    // The whole of this block is the content of the helper
                    // memory region.
                    if (this.helper != null) {
                        log.appendMsg(String.format("Reading %d bytes of helper program image", size));
                        this.helper.content = reader.readNextByteArray(size);
                    } else {
                        log.appendMsg("Ignoring helper program image because we have no memory region for it");
                    }
                    break;
                case "CUST":
                    // This is the custom chips memory block, which always
                    // appears at a fixed address in the memory map.
                    log.appendMsg("Reading custom chip register values");
                    this.customChips = new MemoryRegion(0xDF0000, 0x200, reader.readNextByteArray(0x200));
                    break;
                default:
                    // We'll ignore unknown chunk types.
                    continue;
            }
        }

        if (!seenHead) {
            // If we didn't see a HEAD chunk then we can't do anything useful
            // with this file.
            throw new IOException("dump file does not have a HEAD chunk");
        }
    }

    public static class MemoryRegion {
        public long start;
        public long length;
        public byte[] content;

        public MemoryRegion(long start, long length) {
            this.start = start;
            this.length = length;
        }

        public MemoryRegion(long start, long length, byte[] content) {
            this(start, length);
            this.content = content;
        }
    }
}
