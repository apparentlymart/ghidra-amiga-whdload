package whdload;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

public class WHDLoadHelperHeader {
    public int whdloadVersion;
    public int flags;
    public long baseMemSize;
    public short gameLoaderOffset;
    public short currentDirOffset;
    public short dontCacheOffset;
    public short nameOffset;
    public short copyOffset;
    public short infoOffset;
    public short kickNameOffset;
    public short configOffset;

    public WHDLoadHelperHeader(ByteProvider srcProvider) throws IOException {
        BinaryReader reader = new BinaryReader(srcProvider, false);
        reader.setPointerIndex(4); // ws_ID field of the header (skipped ws_Security)
        String id = reader.readNextAsciiString(8);
        if (!id.equals("WHDLOADS")) {
            throw new IOException("Helper program header does not have 'WHDLOADS' marker");
        }

        this.whdloadVersion = reader.readNextUnsignedShort();
        this.flags = reader.readNextUnsignedShort();
        this.baseMemSize = reader.readNextUnsignedInt();
        reader.readNextUnsignedInt(); // skip unused ws_ExecInstall
        this.gameLoaderOffset = reader.readNextShort();
        this.currentDirOffset = reader.readNextShort();
        this.dontCacheOffset = reader.readNextShort();

        if (this.whdloadVersion >= 10) {
            reader.setPointerIndex(36); // ws_name field
            this.nameOffset = reader.readNextShort();
            this.copyOffset = reader.readNextShort();
            this.infoOffset = reader.readNextShort();
        }

        if (this.whdloadVersion >= 16) {
            this.kickNameOffset = reader.readShort(42);
        }

        if (this.whdloadVersion >= 17) {
            this.configOffset = reader.readShort(50);
        }
    }
}
