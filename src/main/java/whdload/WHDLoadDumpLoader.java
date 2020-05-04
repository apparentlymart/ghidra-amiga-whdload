package whdload;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import structs.WHDLoadSlave;

public class WHDLoadDumpLoader extends AbstractLibrarySupportLoader {

    @Override
    public String getName() {
        return "Amiga WHDLoad Dump File";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        if (WHDLoadDumpFile.isDumpFile(new BinaryReader(provider, false))) {
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:default", "default"), true));
        }

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
            TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
        FlatProgramAPI fpa = new FlatProgramAPI(program);
        Memory mem = program.getMemory();
        BinaryReader reader = new BinaryReader(provider, false);

        WHDLoadDumpFile dumpFile = new WHDLoadDumpFile(reader, monitor, log);
        log.appendMsg("Read the WHDLoad dump file");

        if (dumpFile.baseMem != null) {
            log.appendMsg("Creating base memory block");
            this.createMemoryBlock("BaseMem", dumpFile.baseMem, fpa, log);
        }
        if (dumpFile.expMem != null) {
            log.appendMsg("Creating expansion memory block");
            this.createMemoryBlock("ExpMem", dumpFile.expMem, fpa, log);
        }
        if (dumpFile.helper != null) {
            log.appendMsg("Creating helper program memory block");
            String name = dumpFile.helperName != null ? dumpFile.helperName : "Helper";
            this.createMemoryBlock(name, dumpFile.helper, fpa, log);
        }
        // if (dumpFile.resLoad != null) {
        // log.appendMsg("Creating ResidentLoader memory block");
        // this.createMemoryBlock("ResLoad", dumpFile.resLoad, fpa, log);
        // }
        if (dumpFile.customChips != null) {
            log.appendMsg("Creating custom chips memory block");
            this.createMemoryBlock("CustomChips", dumpFile.customChips, fpa, log);
        }

        // If we have the content of the helper program then we can do some
        // further analysis to annotate the header and the entry point.
        if (dumpFile.helper != null && dumpFile.helper.content != null) {
            ByteProvider headerProvider = new ByteArrayProvider(dumpFile.helper.content);
            WHDLoadHelperHeader header = new WHDLoadHelperHeader(headerProvider);
            log.appendMsg(String.format("This helper targets WHDLoad v%d", header.whdloadVersion));
            try {
                DataType headerType = program.getDataTypeManager().addDataType(
                        (new WHDLoadSlave(header.whdloadVersion)).toDataType(),
                        DataTypeConflictHandler.DEFAULT_HANDLER);
                DataUtilities.createData(program, fpa.toAddr(dumpFile.helper.start), headerType, -1, false,
                        ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
            } catch (DuplicateNameException | IOException | CodeUnitInsertionException e) {
                log.appendException(e);
            }
        }
    }

    private MemoryBlock createMemoryBlock(String name, WHDLoadDumpFile.MemoryRegion spec, FlatProgramAPI fpa,
            MessageLog log) {

        InputStream stream = null;
        if (spec.content != null) {
            log.appendMsg(String.format("%s block has a memory image of %d bytes", name, spec.content.length));
            stream = new ByteArrayInputStream(spec.content);
        } else {
            log.appendMsg(String.format("%s block has unknown content", name));
        }

        try {
            Program program = fpa.getCurrentProgram();
            int transId = program.startTransaction(
                    String.format("Create %s block at 0x%08x (%d bytes)", name, spec.start, spec.length));
            MemoryBlock block = fpa.createMemoryBlock(name, fpa.toAddr(spec.start), stream, spec.length, false);
            program.endTransaction(transId, true);

            block.setExecute(true);
            block.setRead(true);
            block.setWrite(true);

            return block;
        } catch (Exception e) {
            log.appendException(e);
            return null;
        }
    }

}
