import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
  NetworkByteSwap() {
    exists(MacroInvocation mi |
      mi.getMacroName().regexpMatch("ntoh.*") and this = mi.getExpr()
    )
  }
}

class Config extends TaintTracking::Configuration {
  Config() {
    this = "NetorkToMemFuncLength"
  }

  override predicate isSource(DataFlow::Node source) {
    exists(NetworkByteSwap nbs | 
      source.asExpr() = nbs
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fn |
      fn.getTarget().getName() = "memcpy" and fn.getArgument(2) = sink.asExpr()
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"


