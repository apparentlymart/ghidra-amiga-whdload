package structs;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FactoryStructureDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.HashMap;
import java.util.Map;

import ghidra.docking.settings.Settings;

public class ResloadPatchList extends FactoryStructureDataType {
    DataType cmdEnum;

    public ResloadPatchList() {
        this(null);
    }

    public ResloadPatchList(DataTypeManager dtm) {
        super("resload_PatchList", dtm);

        Enum cmdEnum = new EnumDataType("Resload_PLCMD", 2);
        cmdEnum.add("PLCMD_WORDADR", 0x8000);
        cmdEnum.add("PLCMD_CTRL", 0x4000);
        for (PatchListCommand cmd : PatchListCommand.values()) {
            cmdEnum.add("PLCMD_" + cmd.name(), cmd.value);
        }
        this.cmdEnum = cmdEnum;
    }

    public String getMnemonic(Settings settings) {
        return "rl_PatchList";
    }

    @Override
    public String getDescription() {
        return "resload_Patch patch list";
    }

    @Override
    protected void populateDynamicStructure(MemBuffer buf, Structure out) {
        Map<PatchListCommand, Structure> longAddrStructs = new HashMap<>();
        Map<PatchListCommand, Structure> shortAddrStructs = new HashMap<>();
        Map<PatchListCommand, Structure> controlStructs = new HashMap<>();

        try {
            int i = 0;
            while (true) {
                int cmdRaw = buf.getUnsignedShort(i);
                if (cmdRaw == 0) {
                    // PL_END
                    out.add(cmdEnum);
                    return;
                }
                boolean wordAddr = (cmdRaw & 0x8000) != 0;
                boolean control = (cmdRaw & 0x4000) != 0;
                cmdRaw = cmdRaw & 0x3F;

                Map<PatchListCommand, Structure> existing;
                if (control) {
                    existing = controlStructs;
                } else if (wordAddr) {
                    existing = shortAddrStructs;
                } else {
                    existing = longAddrStructs;
                }

                PatchListCommand cmd = PatchListCommand.byValue(cmdRaw);
                Structure struct = existing.getOrDefault(cmd, null);
                if (struct == null) {
                    String name = "Resload_PatchList_" + cmd.name();
                    if (wordAddr && !control) {
                        name += "_w";
                    }
                    struct = new StructureDataType(name, 0);
                    struct.add(this.cmdEnum, "cmd", "Command");
                    if (!control) {
                        if (wordAddr) {
                            struct.add(UnsignedShortDataType.dataType, "addr", "Address");
                        } else {
                            struct.add(UnsignedIntegerDataType.dataType, "addr", "Address");
                        }
                    }
                    cmd.addFields(struct); // command might take additional arguments
                    existing.put(cmd, struct); // for next time
                }

                out.add(struct);
                i += struct.getLength(); // skip over the command we just annotated

                // As a special case, the "DATA" command contains a length for
                // a span of bytes that it consumes after it, rounded up to
                // end on an even byte. That isn't accounted for by
                // the addFields method, so we'll handle it here by tacking
                // on a byte array covering those extra bytes. We don't include
                // the byte array inside the instruction struct because that
                // would make each distinct length require a different
                // instruction struct, which is overkill.
                if (cmd == PatchListCommand.DATA) {
                    // The length appears either four or six bytes after
                    // the command word, depending on the length of the
                    // address.
                    int lengthOffset = wordAddr ? 4 : 6;
                    int length = buf.getUnsignedShort(i + lengthOffset);
                    if (length > 0) { // ghidra doesn't support zero-length types
                        DataType arrayType = new ArrayDataType(ByteDataType.dataType, length, 1);
                        out.add(arrayType);
                        i += length; // skip over the array we just annotated
                    }
                }

            }
        } catch (MemoryAccessException e) {
            return;
        }
    }

    public boolean isDynamicallySized() {
        return true;
    }

    @Override
    public DataType clone(DataTypeManager dtm) {
        return new ResloadPatchList(dtm);
    }

    private enum PatchListCommand {
        END(0), R(1), P(2) {
            void addFields(Structure struct) {
                struct.add(ShortDataType.dataType, "destination", "Destination");
            }
        },
        PS(3) {
            void addFields(Structure struct) {
                struct.add(ShortDataType.dataType, "destination", "Destination");
            }
        },
        S(4) {
            void addFields(Structure struct) {
                struct.add(ShortDataType.dataType, "distance", "Distance");
            }
        },
        I(5), B(6) {
            void addFields(Structure struct) {
                struct.add(ByteDataType.dataType, "unused", "Unused");
                struct.add(ByteDataType.dataType, "data", "Data to write");
            }
        },
        W(7) {
            void addFields(Structure struct) {
                struct.add(UnsignedShortDataType.dataType, "data", "Data to write");
            }
        },
        L(8) {
            void addFields(Structure struct) {
                struct.add(UnsignedIntegerDataType.dataType, "data", "Data to write");
            }
        },
        A(9) {
            void addFields(Structure struct) {
                struct.add(UnsignedIntegerDataType.dataType, "data", "Data to write");
            }
        },
        PA(10) {
            void addFields(Structure struct) {
                struct.add(ShortDataType.dataType, "destination", "Destination");
            }
        },
        NOP(11) {
            void addFields(Structure struct) {
                struct.add(UnsignedShortDataType.dataType, "length", "Length to fill in bytes");
            }
        },
        C(12) {
            void addFields(Structure struct) {
                struct.add(UnsignedShortDataType.dataType, "length", "Length to clear in bytes");
            }
        },
        CB(13), CW(14), CL(15), PSS(16) {
            void addFields(Structure struct) {
                struct.add(ShortDataType.dataType, "destination", "Destination");
                struct.add(UnsignedShortDataType.dataType, "length", "Length to fill in bytes");
            }
        },
        NEXT(17) {
            void addFields(Structure struct) {
                struct.add(ShortDataType.dataType, "destination", "Destination");
            }
        },
        AB(18) {
            void addFields(Structure struct) {
                struct.add(ByteDataType.dataType, "unused", "Unused");
                struct.add(ByteDataType.dataType, "value", "Value to add");
            }
        },
        AW(19) {
            void addFields(Structure struct) {
                struct.add(ShortDataType.dataType, "value", "Value to add");
            }
        },
        AL(20) {
            void addFields(Structure struct) {
                struct.add(IntegerDataType.dataType, "value", "Value to add");
            }
        },
        DATA(21) {
            void addFields(Structure struct) {
                struct.add(UnsignedShortDataType.dataType, "length", "Number of bytes of data that follow");
            }
        },
        ORB(22) {
            void addFields(Structure struct) {
                struct.add(ByteDataType.dataType, "unused", "Unused");
                struct.add(ByteDataType.dataType, "value", "Value to or");
            }
        },
        ORW(23) {
            void addFields(Structure struct) {
                struct.add(UnsignedShortDataType.dataType, "value", "Value to or");
            }
        },
        ORL(24) {
            void addFields(Structure struct) {
                struct.add(UnsignedIntegerDataType.dataType, "value", "Value to or");
            }
        },
        GA(25) {
            void addFields(Structure struct) {
                struct.add(ShortDataType.dataType, "destination", "destination");
            }
        },
        BKPT(26), BELL(27) {
            void addFields(Structure struct) {
                struct.add(UnsignedShortDataType.dataType, "time", "time to wait");
            }
        },
        IFBW(28), IFC1(29), IFC2(30), IFC3(31), IFC4(32), IFC5(33), IFC1X(34), IFC2X(35), IFC3X(36), IFC4X(37),
        IFC5X(38), ELSE(39), ENDIF(40);

        final int value;

        PatchListCommand(int value) {
            this.value = value;
        }

        static PatchListCommand byValue(int value) {
            for (PatchListCommand cmd : PatchListCommand.values()) {
                if (cmd.value == value) {
                    return cmd;
                }
            }
            return END;
        }

        void addFields(Structure struct) {
            // no additional fields by default
        }
    }
}
