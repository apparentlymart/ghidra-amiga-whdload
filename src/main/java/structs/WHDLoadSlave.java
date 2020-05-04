package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class WHDLoadSlave implements StructConverter {
    private int whdloadVersion;

    public WHDLoadSlave(int whdloadVersion) {
        this.whdloadVersion = whdloadVersion;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure s = new StructureDataType("WHDLoadSlave", 0);

        s.add(new ArrayDataType(BYTE, 4, 1), "ws_Security", "moveq #-1,d0 rts");
        s.add(new ArrayDataType(BYTE, 8, 1), "ws_ID", "WHDLOADS");
        s.add(WORD, "ws_Version", "required WHDLoad version");
        s.add(WORD, "ws_Flags", "configuration flags"); // TODO: Make this an enum
        s.add(DWORD, "ws_BaseMemSize", "size of required base memory");
        s.add(DWORD, "ws_ExecInstall", "must be zero");
        s.add(WORD, "ws_GameLoader", "base-relative pointer to entry point");
        s.add(WORD, "ws_CurrentDir", "base-relative pointer to data directory name");
        s.add(WORD, "ws_DontCache", "base-relative pointer to pattern for files not to cache");

        if (this.whdloadVersion < 4) {
            return s;
        }

        s.add(BYTE, "ws_keydebug", "raw key code to quit with debug");
        s.add(BYTE, "ws_keyexit", "raw key code to exit");

        if (this.whdloadVersion < 8) {
            return s;
        }

        s.add(DWORD, "ws_ExpMem", "size of or location of expansion memory");

        if (this.whdloadVersion < 10) {
            return s;
        }

        s.add(WORD, "ws_name", "base-relative pointer to name of installed program");
        s.add(WORD, "ws_copy", "base-relative pointer to copyright information");
        s.add(WORD, "ws_info", "base-relative pointer to additional information");

        if (this.whdloadVersion < 16) {
            return s;
        }

        s.add(WORD, "ws_kickname", "base-relative pointer to name of kickstart image");
        s.add(DWORD, "ws_kicksize", "expected size of kickstart image");
        s.add(WORD, "ws_kickcrc", "expected CRC16 of kickstart image");

        if (this.whdloadVersion < 17) {
            return s;
        }

        s.add(WORD, "ws_config", "base-relative pointer to splash configuration");

        return s;
    }

}
