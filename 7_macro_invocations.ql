import cpp

from MacroInvocation mi, Macro m
where mi.getMacro() = m and m.getName().regexpMatch("ntoh.*")
select mi