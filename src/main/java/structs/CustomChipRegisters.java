package structs;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class CustomChipRegisters implements StructConverter {

    @Override
    public DataType toDataType() throws DuplicateNameException, IOException {
        Structure s = new StructureDataType("CustomChipRegisters", 0);
        for (String name : REGISTER_NAMES) {
            s.add(WORD, 2, name, "");
        }
        return s;
    }

    static String[] REGISTER_NAMES = { "BLTDDAT", "DMACONR", "VPOSR", "VHPOSR", "DSKDATR", "JOY0DAT", "JOT1DAT",
            "CLXDAT", "ADKCONR", "POT0DAT", "POT1DAT", "POTGOR", "SERDATR", "DSKBYTR", "INTENAR", "INTREQR", "DSKPTH",
            "DSKPTL", "DSKLEN", "DSKDAT", "REFPTR", "VPOSW", "VHPOSW", "COPCON", "SERDAT", "SERPER", "POTGO", "JOYTEST",
            "STREQU", "STRVBL", "STRHOR", "STRLONG", "BLTCON0", "BLTCON1", "BLTAFWM", "BLTALWM", "BLTCPTH", "BLTCPTL",
            "BLTBPTH", "BLTBPTL", "BLTAPTH", "BLTAPTL", "BLTDPTH", "BLTDPTL", "BLTSIZE", "BLTCON0L", "BLTSIZV",
            "BLTSIZH", "BLTCMOD", "BLTBMOD", "BLTAMOD", "BLTDMOD", "RESERVED1", "RESERVED2", "RESERVED3", "RESERVED4",
            "BLTCDAT", "BLTBDAT", "BLTADAT", "RESERVED5", "SPRHDAT", "BPLHDAT", "LISAID", "DSKSYNC", "COP1LCH",
            "COP1LCL", "COP2LCH", "COP2LCL", "COPJMP1", "COPJMP2", "COPINS", "DIWSTRT", "DIWSTOP", "DDFSTRT", "DDFSTOP",
            "DMACON", "CLXCON", "INTENA", "INTREQ", "ADKCON", "AUD0LCH", "AUD0LCL", "AUD0LEN", "AUD0PER", "AUD0VOL",
            "AUD0DAT", "RESERVED6", "RESERVED7", "AUD1LCH", "AUD1LCL", "AUD1LEN", "AUD1PER", "AUD1VOL", "AUD1DAT",
            "RESERVED8", "RESERVED9", "AUD2LCH", "AUD2LCL", "AUD2LEN", "AUD2PER", "AUD2VOL", "AUD2DAT", "RESERVED10",
            "RESERVED11", "AUD3LCH", "AUD3LCL", "AUD3LEN", "AUD3PER", "AUD3VOL", "AUD3DAT", "RESERVED12", "RESERVED13",
            "BPL1PTH", "BPL1PTL", "BPL2PTH", "BPL2PTL", "BPL3PTH", "BPL3PTL", "BPL4PTH", "BPL4PTL", "BPL5PTH",
            "BPL5PTL", "BPL6PTH", "BPL6PTL", "BPL7PTH", "BPL7PTL", "BPL8PTH", "BPL8PTL", "BPLCON0", "BPLCON1",
            "BPLCON2", "BPLCON3", "BPL1MOD", "BPL2MOD", "BPLCON4", "CLXCON2", "BPL1DAT", "BPL2DAT", "BPL3DAT",
            "BPL4DAT", "BPL5DAT", "BPL6DAT", "BPL7DAT", "BPL8DAT", "SPR0PTH", "SPR0PTL", "SPR1PTH", "SPR1PTL",
            "SPR2PTH", "SPR2PTL", "SPR3PTH", "SPR3PTL", "SPR4PTH", "SPR4PTL", "SPR5PTH", "SPR5PTL", "SPR6PTH",
            "SPR6PTL", "SPR7PTH", "SPR7PTL", "SPR0POS", "SPR0CTL", "SPR0DATA", "SPR0DATB", "SPR1POS", "SPR1CTL",
            "SPR1DATA", "SPR1DATB", "SPR2POS", "SPR2CTL", "SPR2DATA", "SPR2DATB", "SPR3POS", "SPR3CTL", "SPR3DATA",
            "SPR3DATB", "SPR4POS", "SPR4CTL", "SPR4DATA", "SPR4DATB", "SPR5POS", "SPR5CTL", "SPR5DATA", "SPR5DATB",
            "SPR6POS", "SPR6CTL", "SPR6DATA", "SPR6DATB", "SPR7POS", "SPR7CTL", "SPR7DATA", "SPR7DATB", "COLOR00",
            "COLOR01", "COLOR02", "COLOR03", "COLOR04", "COLOR05", "COLOR06", "COLOR07", "COLOR08", "COLOR09",
            "COLOR10", "COLOR11", "COLOR12", "COLOR13", "COLOR14", "COLOR15", "COLOR16", "COLOR17", "COLOR18",
            "COLOR19", "COLOR20", "COLOR21", "COLOR22", "COLOR23", "COLOR24", "COLOR25", "COLOR26", "COLOR27",
            "COLOR28", "COLOR29", "COLOR30", "COLOR31", "HTOTAL", "HSSTOP", "HBSTRT", "HBSTOP", "VTOTAL", "VSSTOP",
            "VBSTRT", "VBSTOP", "SPRHSTRT", "SPRHSTOP", "BPLHSTRT", "BPLHSTOP", "HHPOSW", "HHPOSR", "BEAMCON0",
            "HSSTRT", "VSSTRT", "HCENTER", "DIWHIGH", "BPLHMOD", "SPRHPTH", "SPRHPTL", "BPLHPTH", "BPLHPTL",
            "RESERVED14", "RESERVED15", "RESERVED16", "RESERVED17", "RESERVED18", "RESERVED19", "FMODE", "NOOP", };
}