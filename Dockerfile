FROM scratch 

ADD bin/superproxy-amd64-linux /superproxy 
ENTRYPOINT /superproxy