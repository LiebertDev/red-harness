// Red Harness Ghidra script (Java GhidraScript; does NOT require PyGhidra).
//
// One script, four operations: analyze (export after import+analysis), decompile, xrefs, disassemble. Probing is done on
// the Python side. Argument: path to a single .properties request file.
//
// RESULT CHANNEL: the result is NEVER written to stdout (it mixes with Ghidra log lines and stdout may be head+tail
// truncated). The result is written to the request's `result` file via tmp + atomic move. The document carries
// "complete":true only if the script ran to the end, and that field is written LAST; counts are part of the document,
// and the Python side does not accept a truncated/partial document (no complete, counts mismatch, nonce mismatch) as OK.
//
// Does NOT modify the program (to avoid triggering needless re-analysis): read-only.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public class RHQuery extends GhidraScript {
    private static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private Address addr(long off) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off);
    }

    private String blockName(Address a) {
        MemoryBlock mb = currentProgram.getMemory().getBlock(a);
        return mb == null ? "" : mb.getName();
    }

    private Function resolve(Properties req) throws Exception {
        String name = req.getProperty("function_name");
        if (name != null) {
            List<Function> hits = new ArrayList<>();
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext()) {
                Function f = it.next();
                if (f.getName().equals(name)) hits.add(f);
            }
            if (hits.isEmpty()) throw new IllegalArgumentException("LOOKUP: could not resolve name: " + name);
            if (hits.size() > 1) throw new IllegalArgumentException("LOOKUP: ambiguous name (" + hits.size() + " matches): " + name);
            return hits.get(0);
        }
        long ea = Long.parseLong(req.getProperty("function_addr"));
        Function f = currentProgram.getFunctionManager().getFunctionContaining(addr(ea));
        if (f == null) throw new IllegalArgumentException(String.format("LOOKUP: no function at address: 0x%x", ea));
        return f;
    }

    private String opAnalyze() throws Exception {
        // Analysis convergence race: if enumeration runs before deferred analyzers finish,
        // the function list is incomplete. analyzeChanges blocks on the real convergence signal; free if no work is pending.
        // Patches such as waiting/retrying/comparing twice are NOT used.
        analyzeChanges(currentProgram);
        boolean stillAnalyzing = AutoAnalysisManager.getAnalysisManager(currentProgram).isAnalyzing();

        StringBuilder fs = new StringBuilder("[");
        int nf = 0;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (monitor.isCancelled()) throw new CancelledException();
            if (nf++ > 0) fs.append(',');
            Address ep = f.getEntryPoint();
            fs.append("{\"address\":").append(ep.getOffset())
              .append(",\"name\":").append(q(f.getName()))
              .append(",\"size\":").append(f.getBody().getNumAddresses())
              .append(",\"thunk\":").append(f.isThunk())
              .append(",\"chunks\":").append(f.getBody().getNumAddressRanges())
              .append(",\"block\":").append(q(blockName(ep)))
              .append(",\"source\":").append(q(f.getSymbol().getSource().toString())).append('}');
        }
        fs.append(']');

        StringBuilder ss = new StringBuilder("[");
        int ns = 0;
        DataIterator dit = currentProgram.getListing().getDefinedData(true);
        while (dit.hasNext()) {
            Data d = dit.next();
            if (monitor.isCancelled()) throw new CancelledException();
            if (!StringDataInstance.isString(d)) continue;
            StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
            String v = sdi == null ? null : sdi.getStringValue();
            if (v == null) continue;
            if (ns++ > 0) ss.append(',');
            ss.append("{\"address\":").append(d.getAddress().getOffset())
              .append(",\"length\":").append(d.getLength())
              .append(",\"kind\":").append(q(d.getDataType().getName()))
              .append(",\"value\":").append(q(v)).append('}');
        }
        ss.append(']');

        Long entry = null;
        for (Address a : currentProgram.getSymbolTable().getExternalEntryPointIterator()) {
            Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
            if (entry == null || (s != null && s.getName().equals("entry"))) entry = a.getOffset();
        }
        int external = currentProgram.getFunctionManager().getFunctionCount() - nf;
        String info = "{\"arch\":" + q(currentProgram.getLanguage().getProcessor().toString())
            + ",\"bits\":" + currentProgram.getLanguage().getLanguageDescription().getSize()
            + ",\"entry\":" + entry
            + ",\"decompiler\":true"
            + ",\"imagebase\":" + currentProgram.getImageBase().getOffset()
            + ",\"language\":" + q(currentProgram.getLanguageID().toString())
            + ",\"compiler\":" + q(currentProgram.getCompilerSpec().getCompilerSpecID().toString())
            + ",\"external_function_count\":" + external
            + ",\"still_analyzing\":" + stillAnalyzing + "}";
        return "\"functions\":" + fs + ",\"strings\":" + ss + ",\"info\":" + info
            + ",\"counts\":{\"functions\":" + nf + ",\"strings\":" + ns + "}";
    }

    private String opDecompile(Properties req) throws Exception {
        Function f = resolve(req);
        int tmo = Integer.parseInt(req.getProperty("decompile_timeout", "120"));
        DecompInterface di = new DecompInterface();
        try {
            di.setOptions(new DecompileOptions());
            di.toggleCCode(true);
            di.toggleSyntaxTree(false);
            if (!di.openProgram(currentProgram)) throw new RuntimeException("DECOMPILER_UNAVAILABLE: " + di.getLastMessage());
            DecompileResults res = di.decompileFunction(f, tmo, monitor);
            if (res.isTimedOut()) throw new RuntimeException("DECOMPILE_TIMEOUT: " + tmo + " s exceeded");
            if (res.isCancelled()) throw new RuntimeException("DECOMPILE_TIMEOUT: cancelled");
            if (!res.decompileCompleted() || res.getDecompiledFunction() == null)
                throw new RuntimeException("DECOMPILE_FAILED: " + res.getErrorMessage());
            return "\"address\":" + f.getEntryPoint().getOffset() + ",\"name\":" + q(f.getName())
                + ",\"signature\":" + q(f.getSignature().getPrototypeString())
                + ",\"text\":" + q(res.getDecompiledFunction().getC());
        } finally {
            di.dispose();
        }
    }

    private String opXrefs(Properties req) throws Exception {
        long ea = Long.parseLong(req.getProperty("address"));
        int limit = Integer.parseInt(req.getProperty("limit", "200"));
        boolean to = req.getProperty("direction", "to").equals("to");
        List<Reference> all = new ArrayList<>();
        if (to) {
            ReferenceIterator ri = currentProgram.getReferenceManager().getReferencesTo(addr(ea));
            while (ri.hasNext()) all.add(ri.next());
        } else {
            all.addAll(Arrays.asList(currentProgram.getReferenceManager().getReferencesFrom(addr(ea))));
        }
        StringBuilder xs = new StringBuilder("[");
        int n = 0;
        for (Reference r : all) {
            if (n >= limit) break;
            if (n++ > 0) xs.append(',');
            Function f = currentProgram.getFunctionManager().getFunctionContaining(r.getFromAddress());
            Address ta = r.getToAddress();
            Symbol ts = currentProgram.getSymbolTable().getPrimarySymbol(ta);
            String tname = ts == null ? "" : ts.getName();
            String tstr = null, tkind = "";
            Data td = currentProgram.getListing().getDataAt(ta);
            if (td != null && StringDataInstance.isString(td)) {
                StringDataInstance sdi = StringDataInstance.getStringDataInstance(td);
                String sv = sdi == null ? null : sdi.getStringValue();
                if (sv != null) { tstr = sv; tkind = td.getDataType().getName(); }
            }
            xs.append("{\"from\":").append(r.getFromAddress().getOffset())
              .append(",\"to\":").append(r.getToAddress().getOffset())
              .append(",\"kind\":").append(q(r.getReferenceType().getName()))
              .append(",\"is_code\":").append(r.getReferenceType().isFlow())
              .append(",\"from_function\":").append(q(f == null ? "" : f.getName()))
              .append(",\"to_name\":").append(q(tname))
              .append(",\"to_string\":").append(tstr == null ? "null" : q(tstr))
              .append(",\"to_string_kind\":").append(q(tkind)).append('}');
        }
        xs.append(']');
        return "\"xrefs\":" + xs + ",\"total\":" + all.size() + ",\"counts\":{\"xrefs\":" + n + "}";
    }


    // ---- disassemble: common OperandInfo contract (engines/base.py). Integers are two's complement; Python masks them.
    private static final java.util.regex.Pattern SCALE = java.util.regex.Pattern.compile("\\*\\s*(0x[0-9a-fA-F]+|\\d+)");

    private static boolean hasOnlyScalar(Object[] objs) {
        boolean any = false;
        for (Object o : objs) {
            if (o instanceof Scalar) any = true;
            else if (o instanceof Address) return false;  // if both Address and Scalar are present, it is not a real branch/call
        }
        return any;
    }

    private String operandJson(Instruction ins, int i) {
        int t = ins.getOperandType(i);
        String text = ins.getDefaultOperandRepresentation(i);
        String k = "other", reg = "", base = "", index = "";
        int scale = 0, size = 0;
        Long disp = null, value = null;
        Object[] objs = ins.getOpObjects(i);
        if (OperandType.isRegister(t) && !OperandType.isDynamic(t)) {
            k = "reg";
            Register r = ins.getRegister(i);
            reg = r == null ? text.toLowerCase() : r.getName().toLowerCase();
            if (r != null) size = r.getBitLength() / 8;
        } else if (OperandType.isDynamic(t) || (OperandType.isAddress(t) && text.contains("["))) {
            k = "mem";
            List<String> regs = new ArrayList<>();
            long sum = 0; boolean anyScalar = false;
            java.util.regex.Matcher m = SCALE.matcher(text);
            Long sc = null;
            if (m.find()) sc = Long.decode(m.group(1));
            boolean scaleSkipped = false;
            for (Object o : objs) {
                if (o instanceof Register) regs.add(((Register) o).getName().toLowerCase());
                else if (o instanceof Scalar) {
                    long v = ((Scalar) o).getSignedValue();
                    if (sc != null && !scaleSkipped && v == sc && regs.size() >= 2) { scaleSkipped = true; continue; }
                    sum += v; anyScalar = true;
                } else if (o instanceof Address) {
                    value = ((Address) o).getOffset();
                }
            }
            if (!regs.isEmpty()) base = regs.get(0);
            if (regs.size() > 1) index = regs.get(1);
            if (!index.isEmpty()) scale = sc == null ? 1 : sc.intValue();
            if (regs.isEmpty() && anyScalar && value == null) value = sum;  // [0x10000] absolute
            else disp = sum;
        } else if (OperandType.isScalar(t) || hasOnlyScalar(objs)) {
            // Fixed: `FlowType.isFlow()` returns TRUE even for a plain MOV (fallthrough is a "flow");
            // so an ADDRESS-SHAPED immediate (e.g. a handler address written to a table via "mov [mem], offset handler"
            // -- `objs` here carries a Scalar, NOT a real branch/call target) was wrongly counted as
            // "near" and `value` was never filled (there was no real branch target, so `getFlows()` came back
            // empty) -- the MajorFunction store silently stayed unresolvable (e.g. an
            // IRP_MJ_DEVICE_CONTROL store). Real branch/call targets (NO Scalar in objs, only Address)
            // fall to the "near" branch below; anything carrying a Scalar (push/mov immediate -- same class as
            // IDA's "imm") is counted as "imm" here.
            k = "imm";
            for (Object o : objs) if (o instanceof Scalar) { value = ((Scalar) o).getSignedValue(); size = ((Scalar) o).bitLength() / 8; }
        } else if ((t & OperandType.CODE) != 0 || OperandType.isAddress(t)) {
            k = (ins.getFlowType().isJump() || ins.getFlowType().isCall()) ? "near" : "mem";
            for (Object o : objs) if (o instanceof Address) value = ((Address) o).getOffset();
            if (value == null) { Address[] fl = ins.getFlows(); if (fl.length > 0) value = fl[0].getOffset(); }
        }
        String sym = "";
        try {
            Address symAt = null;
            if (value != null && (k.equals("mem") || k.equals("near"))) symAt = addr(value);
            else if (k.equals("imm") && value != null) {
                for (Reference r : ins.getOperandReferences(i)) symAt = r.getToAddress();
            }
            if (symAt != null) {
                Symbol sy = currentProgram.getSymbolTable().getPrimarySymbol(symAt);
                if (sy != null) sym = sy.getName();
            }
        } catch (Exception e) { sym = ""; }
        StringBuilder b = new StringBuilder("{\"k\":").append(q(k)).append(",\"t\":").append(q(text))
            .append(",\"r\":").append(q(reg)).append(",\"b\":").append(q(base)).append(",\"i\":").append(q(index))
            .append(",\"sc\":").append(scale).append(",\"d\":").append(disp).append(",\"v\":").append(value)
            .append(",\"sz\":").append(size).append(",\"y\":").append(q(sym)).append('}');
        return b.toString();
    }

    private String insnJson(Instruction ins) throws Exception {
        StringBuilder b = new StringBuilder("{\"a\":").append(ins.getAddress().getOffset())
            .append(",\"s\":").append(ins.getLength()).append(",\"b\":\"");
        for (byte x : ins.getBytes()) b.append(String.format("%02x", x & 0xff));
        b.append("\",\"m\":").append(q(ins.getMnemonicString().toLowerCase())).append(",\"t\":").append(q(ins.toString()))
         .append(",\"o\":[");
        for (int i = 0; i < ins.getNumOperands(); i++) {
            if (i > 0) b.append(',');
            b.append(operandJson(ins, i));
        }
        return b.append("]}").toString();
    }

    private String opDisassemble(Properties req) throws Exception {
        long start = Long.parseLong(req.getProperty("address"));
        int count = Integer.parseInt(req.getProperty("count", "200"));
        boolean whole = req.getProperty("whole_function", "false").equals("true");
        Function f = currentProgram.getFunctionManager().getFunctionContaining(addr(start));
        List<Instruction> list = new ArrayList<>();
        boolean complete = true;
        String stop = "";
        int total;
        if (whole) {
            if (f == null) throw new IllegalArgumentException(String.format("LOOKUP: no function at address: 0x%x", start));
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            int n = 0;
            while (it.hasNext()) {
                Instruction ins = it.next();
                if (monitor.isCancelled()) throw new CancelledException();
                n++;
                if (list.size() < count) list.add(ins);
            }
            total = n;
            if (n > count) { complete = false; stop = "COUNT: returned " + count + " of " + n + " instructions"; }
        } else {
            Address a = addr(start);
            while (list.size() < count) {
                Instruction ins = currentProgram.getListing().getInstructionAt(a);
                if (ins == null) { complete = false; stop = String.format("NOT_CODE: 0x%x", a.getOffset()); break; }
                list.add(ins);
                a = ins.getMaxAddress().add(1);
            }
            if (complete) { complete = false; stop = "COUNT: " + count + " instructions"; }
            total = list.size();
        }
        StringBuilder xs = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) xs.append(',');
            xs.append(insnJson(list.get(i)));
        }
        xs.append(']');
        return "\"insns\":" + xs + ",\"function_address\":" + (f == null ? "null" : String.valueOf(f.getEntryPoint().getOffset()))
            + ",\"function_name\":" + q(f == null ? "" : f.getName()) + ",\"total\":" + total
            + ",\"full\":" + complete + ",\"stop_reason\":" + q(stop)
            + ",\"counts\":{\"insns\":" + list.size() + "}";
    }

    // ---- decode: linear decoding WITHOUT changing the program (PseudoDisassembler) up to a return/unconditional jump
    private String opDecode(Properties req) throws Exception {
        long start = Long.parseLong(req.getProperty("address"));
        int count = Integer.parseInt(req.getProperty("count", "64"));
        ghidra.app.util.PseudoDisassembler pd = new ghidra.app.util.PseudoDisassembler(currentProgram);
        List<Instruction> list = new ArrayList<>();
        Address a = addr(start);
        boolean complete = false;
        String stop = "COUNT: " + count + " instructions";
        while (list.size() < count) {
            Instruction ins = currentProgram.getListing().getInstructionAt(a);
            if (ins == null) {
                try { ins = pd.disassemble(a); } catch (Exception e) { ins = null; }
            }
            if (ins == null) { stop = String.format("NOT_CODE: 0x%x", a.getOffset()); break; }
            list.add(ins);
            ghidra.program.model.symbol.FlowType ft = ins.getFlowType();
            if (ft.isTerminal() || (ft.isJump() && ft.isUnConditional())) { complete = true; stop = ""; break; }
            a = ins.getMaxAddress().add(1);
        }
        StringBuilder xs = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) xs.append(',');
            xs.append(insnJson(list.get(i)));
        }
        xs.append(']');
        return "\"insns\":" + xs + ",\"function_address\":null,\"function_name\":\"\",\"total\":" + list.size()
            + ",\"full\":" + complete + ",\"stop_reason\":" + q(stop) + ",\"counts\":{\"insns\":" + list.size() + "}";
    }

    // ---- callargs: stack-parameter bytes of each call's callee prototype (from the stack pointer at the call)
    private Function calleeOf(Instruction ins) {
        FunctionManager fm = currentProgram.getFunctionManager();
        for (Address a : ins.getFlows()) {
            Function f = fm.getFunctionAt(a);
            if (f != null) return f.isThunk() ? f.getThunkedFunction(true) : f;
        }
        for (Reference r : ins.getReferencesFrom()) {
            Address to = r.getToAddress();
            if (to.isExternalAddress()) {
                Function f = fm.getFunctionAt(to);
                if (f != null) return f;
            }
            Data d = currentProgram.getListing().getDataAt(to);
            if (d != null && d.isPointer() && d.getValue() instanceof Address) {
                Function f = fm.getFunctionAt((Address) d.getValue());
                if (f != null) return f.isThunk() ? f.getThunkedFunction(true) : f;
            }
        }
        return null;
    }

    private String opCallArgs(Properties req) throws Exception {
        long ea = Long.parseLong(req.getProperty("address"));
        Function f = currentProgram.getFunctionManager().getFunctionContaining(addr(ea));
        if (f == null) throw new IllegalArgumentException(String.format("LOOKUP: no function at address: 0x%x", ea));
        int ptr = currentProgram.getDefaultPointerSize();
        StringBuilder xs = new StringBuilder("[");
        int n = 0;
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (monitor.isCancelled()) throw new CancelledException();
            if (!ins.getFlowType().isCall()) continue;
            Function c = calleeOf(ins);
            String e = "null";
            if (c != null && c.getSignatureSource() != SourceType.DEFAULT && !c.hasVarArgs()) {
                long ext = 0;
                boolean ok = true;
                for (Parameter p : c.getParameters()) {
                    if (p.isStackVariable()) ext = Math.max(ext, p.getStackOffset() + Math.max(p.getLength(), ptr) - ptr);
                    else if (!p.isRegisterVariable()) ok = false;
                }
                if (ok) e = String.valueOf(ext);
            }
            if (n++ > 0) xs.append(',');
            xs.append("{\"a\":").append(ins.getAddress().getOffset()).append(",\"e\":").append(e).append('}');
        }
        xs.append(']');
        return "\"calls\":" + xs + ",\"function_address\":" + f.getEntryPoint().getOffset()
            + ",\"counts\":{\"calls\":" + n + "}";
    }

    private static void writeAtomic(String path, String text) throws IOException {
        Path p = Paths.get(path);
        Path tmp = p.resolveSibling(p.getFileName() + ".tmp");
        try (FileOutputStream os = new FileOutputStream(tmp.toFile())) {
            os.write(text.getBytes(StandardCharsets.UTF_8));
            os.flush();
            os.getFD().sync();
        }
        Files.move(tmp, p, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) { printerr("usage: RHQuery.java <request.properties>"); return; }
        Properties req = new Properties();
        try (Reader r = new InputStreamReader(new FileInputStream(args[0]), StandardCharsets.UTF_8)) { req.load(r); }
        String result = req.getProperty("result");
        String op = req.getProperty("op");
        String nonce = req.getProperty("nonce", "");
        String body;
        try {
            switch (op) {
                case "analyze": body = opAnalyze(); break;
                case "decompile": body = opDecompile(req); break;
                case "xrefs": body = opXrefs(req); break;
                case "disassemble": body = opDisassemble(req); break;
                case "callargs": body = opCallArgs(req); break;
                case "decode": body = opDecode(req); break;
                default: throw new IllegalArgumentException("unknown op: " + op);
            }
            // "complete" is the LAST field: it cannot be present in a half-written/truncated document.
            writeAtomic(result, "{\"ok\":true,\"op\":" + q(op) + ",\"nonce\":" + q(nonce) + "," + body
                + ",\"complete\":true}");
        } catch (Throwable t) {
            writeAtomic(result, "{\"ok\":false,\"op\":" + q(op) + ",\"nonce\":" + q(nonce) + ",\"error\":"
                + q(t.getClass().getSimpleName() + ": " + t.getMessage()) + ",\"complete\":true}");
        }
    }
}
