package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.util.exception.DuplicateNameException;

public class ResidentLoader implements StructConverter {
    private int whdloadVersion;

    public ResidentLoader(int whdloadVersion) {
        this.whdloadVersion = whdloadVersion;
    }

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure s = new StructureDataType("ResidentLoader", 0);

        for (FunctionDef def : FUNCS) {
            if (this.whdloadVersion >= def.requiredVersion) {
                s.add(DWORD, 4, def.name, "");
            }
        }

        if (this.whdloadVersion < 2) {
            return s;
        }

        return s;
    }

    static final DataType STRING = TerminatedStringDataType.dataType;
    static final FunctionDef[] FUNCS = { new FunctionDef("resload_Install", 1), new FunctionDef("resload_Abort", 1),
            new FunctionDef("resload_LoadFile", 1), new FunctionDef("resload_SaveFile", 1),
            new FunctionDef("resload_SetCACR", 1), new FunctionDef("resload_ListFiles", 1),
            new FunctionDef("resload_Decrunch", 1), new FunctionDef("resload_LoadFileDecrunch", 1),
            new FunctionDef("resload_FlushCache", 1), new FunctionDef("resload_GetFileSize", 1),
            new FunctionDef("resload_DiskLoad", 1), new FunctionDef("resload_DiskLoadDev", 2),
            new FunctionDef("resload_CRC16", 3), new FunctionDef("resload_Control", 5),
            new FunctionDef("resload_ProtectRead", 6), new FunctionDef("resload_ProtectReadWrte", 6),
            new FunctionDef("resload_ProtectWrite", 6), new FunctionDef("resload_ProtectRemove", 6),
            new FunctionDef("resload_LoadFileOffset", 6), new FunctionDef("resload_Relocate", 8),
            new FunctionDef("resload_Delay", 8), new FunctionDef("resload_DeleteFile", 8),
            new FunctionDef("resload_ProtectSMC", 10), new FunctionDef("resload_SetCPU", 10),
            new FunctionDef("resload_Patch", 10), new FunctionDef("resload_LoadKick", 11),
            new FunctionDef("resload_Delta", 11), new FunctionDef("resload_GetFileSizeDec", 11),
            new FunctionDef("resload_PatchSeg", 15), new FunctionDef("resload_Examine", 15),
            new FunctionDef("resload_ExNext", 15), new FunctionDef("resload_GetCustom", 15),
            new FunctionDef("resload_VSNPrintF", 18), new FunctionDef("resload_Log", 18) };

    static class FunctionDef {
        String name;
        long requiredVersion;

        public FunctionDef(String name, long requiredVersion) {
            this.name = name;
            this.requiredVersion = requiredVersion;
        }
    }

}
