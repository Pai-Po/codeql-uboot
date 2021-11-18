
/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
        exists( MacroInvocation mc | mc.getMacroName().regexpMatch("ntoh[a-z]*") | this = mc.getExpr() )
    }
}
class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
  }
  override predicate isSink(DataFlow::Node sink) {
    //exists( Function f | f.hasName("memcpy") | sink.asParameter() = f.getParameter(2) )
    //exists( FunctionCall f | f.getTarget().hasName("memcpy") | sink.asParameter() = f.getTarget().getParameter(2) )
    exists( FunctionCall f | f.getTarget().getName() = "memcpy" | sink.asExpr() = f.getArgument(2) )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"