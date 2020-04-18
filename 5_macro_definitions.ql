import cpp

from Macro m
where m.getName() = "ntohs" or m.getName() = "ntohl" or m.getName() = "ntohll"
select m, "a function to convert network byte order buffer to host order integer"

