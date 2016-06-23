#!python

########################################################################################################################
variables = Variables()
variables.Add(BoolVariable("SCAN_BUILD", help="Use LLVM/Clang scan-build as code static analyzer (for Intel/Linux only).", default="no"))
variables.Add("SCAN_REPORTS_DIR", help="Specifies the output directory for static analyzer reports (for Intel/Linux only).", default="scan-build")

########################################################################################################################
env = Environment(variables=variables, CCFLAGS = '-g -std=gnu11')
env.Append(CPPPATH = ['headers'], LIBS=['-lconfig', '-lcrypto', '-lssl', '-lpthread'])

if env["SCAN_BUILD"]:
    enabled_checkers  = " "
    enabled_checkers += "-enable-checker alpha.core.CallAndMessageUnInitRefArg "
    enabled_checkers += "-enable-checker alpha.core.CastSize "
    enabled_checkers += "-enable-checker alpha.core.CastToStruct "
    enabled_checkers += "-enable-checker alpha.core.FixedAddr "
    enabled_checkers += "-enable-checker alpha.core.IdenticalExpr "
    enabled_checkers += "-enable-checker alpha.core.PointerArithm "
    enabled_checkers += "-enable-checker alpha.core.PointerSub "
    enabled_checkers += "-enable-checker alpha.core.SizeofPtr "
    enabled_checkers += "-enable-checker alpha.deadcode.UnreachableCode "
    enabled_checkers += "-enable-checker alpha.security.ArrayBound "
    enabled_checkers += "-enable-checker alpha.security.ArrayBoundV2 "
    enabled_checkers += "-enable-checker alpha.security.MallocOverflow "
    enabled_checkers += "-enable-checker alpha.security.ReturnPtrRange "
    enabled_checkers += "-enable-checker alpha.security.taint.TaintPropagation "
    enabled_checkers += "-enable-checker alpha.unix.MallocWithAnnotations "
    enabled_checkers += "-enable-checker alpha.unix.PthreadLock "
    enabled_checkers += "-enable-checker alpha.unix.SimpleStream "
    enabled_checkers += "-enable-checker alpha.unix.Stream "
    enabled_checkers += "-enable-checker alpha.unix.cstring.BufferOverlap "
    enabled_checkers += "-enable-checker alpha.unix.cstring.NotNullTerminated "
    enabled_checkers += "-enable-checker alpha.unix.cstring.OutOfBounds "
    enabled_checkers += "-enable-checker security.FloatLoopCounter "
    enabled_checkers += "-enable-checker security.insecureAPI.rand "
    enabled_checkers += "-enable-checker security.insecureAPI.strcpy "
    enabled_checkers += "-enable-checker llvm.Conventions "

    disabled_checkers  = " "
#     disabled_checkers += "-disable-checker core.VLASize "

    env["CC"] = "scan-build -analyze-headers -o " + env["SCAN_REPORTS_DIR"] + enabled_checkers + disabled_checkers + env["CC"]
    env["ENV"].update(x for x in env["ENV"].items() if x[0].startswith("CCC_"))

#### SERVER ############################################################################################################
server         = env.Object('src/server/server.c')
server_init    = env.Object('src/server/server_main.c')
hash_table     = env.Object('src/server/hashtable.c')
data_transfer  = env.Object('src/server/data_transfer.c')
ssl_support    = env.Object('src/server/ssl_support.c')
services       = env.Object('src/server/services.c')

server_sources = server + server_init + hash_table + data_transfer + ssl_support + services 
env.Program(target = ['src/server.out'], source = server_sources)
 
#### CLIENT ############################################################################################################
client = env.Object('src/client/client.c')
client_main = env.Object('src/client/client_main.c')
env.Program(target = ['src/client.out'], source = client + client_main)

########################################################################################################################
