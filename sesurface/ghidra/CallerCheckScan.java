// Ghidra headless post-script for sesurface stage H (code-attribution).
//
// Reports in-code call sites where a handler function calls a caller-check
// primitive (getCallingUid / checkCallingPermission / AppOps / *Allowed / peer-cred).
// Walking each function's *callees* (getCalledFunctions) resolves PLT thunks to their
// external targets, so imported checks are caught -- unlike a getReferencesTo on an
// undefined symbol's address, which misses thunked calls.
//
// Output lines:  "CALLERCHECK <caller> -> <callee>"   and a final "CALLERCHECK_TOTAL n".
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.util.Set;

public class CallerCheckScan extends GhidraScript {
    static final String[] NEEDLES = {
        "getCallingUid", "getCallingPid", "checkCallingPermission", "checkPermission",
        "enforceCallingPermission", "enforcePermission", "PermissionController",
        "PermissionChecker", "AppOpsManager", "noteOp", "checkOp", "startOp",
        "AttributionSource", "Allowed", "getpeercon", "SO_PEERSEC", "SO_PEERCRED"
    };

    boolean hit(String n) {
        if (n == null) return false;
        for (String s : NEEDLES) if (n.contains(s)) return true;
        return false;
    }

    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();
        int n = 0;
        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            if (f.isThunk()) continue;              // report the real caller, not the stub
            Set<Function> callees;
            try {
                callees = f.getCalledFunctions(monitor);   // resolves thunks -> externals
            } catch (Exception e) {
                continue;
            }
            for (Function c : callees) {
                String nm = c.getName();
                if (hit(nm)) {
                    println("CALLERCHECK " + f.getName() + " -> " + nm);
                    n++;
                }
            }
        }
        println("CALLERCHECK_TOTAL " + n);
    }
}
