-- V001: Create SecureCloud Messaging Keyspace
-- Replication Strategy: SimpleStrategy with replication_factor 1 for single-datacenter dev/test environments.
-- Production deployments configure NetworkTopologyStrategy across distinct datacenters.

CREATE KEYSPACE IF NOT EXISTS securecloud_messaging
WITH replication = {
    'class': 'SimpleStrategy',
    'replication_factor': 1
};
