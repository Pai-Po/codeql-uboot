import cpp

from MacroInvocation  mi
where mi.getMacroName().regexpMatch("ntoh[a-z]*")
select mi