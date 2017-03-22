#!/bin/bash 

docker run -d --rm -p 2379:2379 -p 2380:2380 \
  --name etcd quay.io/coreos/etcd \
  /usr/local/bin/etcd \
  -name etcd0 \
  -advertise-client-urls http://127.0.0.1:2379 \
  -listen-client-urls http://0.0.0.0:2379 \
  -initial-advertise-peer-urls http://127.0.0.1:2380 \
  -listen-peer-urls http://0.0.0.0:2380 \
  -initial-cluster-token etcd-test-cluster \
  -initial-cluster etcd0=http://127.0.0.1:2380 \
  -initial-cluster-state new