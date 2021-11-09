import cpp

from Macro m
where m.getName().regexpMatch("ntoh[a-z]{1,3}")
select m