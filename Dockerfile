FROM scratch 

ADD bin/superproxy-linux-amd64 /superproxy 
ENTRYPOINT /superproxy