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
            // TODO: The rest of these
    };

    static class FunctionDef {
        String name;
        long requiredVersion;

        public FunctionDef(String name, long requiredVersion) {
            this.name = name;
            this.requiredVersion = requiredVersion;
        }
    }

}
