
import cpp

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
        exists( MacroInvocation mc | mc.getMacroName().regexpMatch("ntoh[a-z]*") | this = mc.getExpr() )
    }
}

from NetworkByteSwap n
select n