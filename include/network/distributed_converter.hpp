#pragma once

#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <functional>

namespace converter::network {

enum class NodeRole {
    COORDINATOR, WORKER, HYBRID
};

enum class NodeStatus {
    AVAILABLE, BUSY, OFFLINE, MAINTENANCE
};

enum class TaskStatus {
    PENDING, ASSIGNED, RUNNING, COMPLETED, FAILED, CANCELLED
};

enum class TaskPriority {
    LOW, NORMAL, HIGH, CRITICAL
};

struct ConversionTask {
    std::string task_id;
    std::string conversion_type;
    std::vector<uint8_t> input_data;
    std::unordered_map<std::string, std::string> parameters;
    TaskPriority priority;
    std::string submitter_id;
    std::string assigned_node;
    TaskStatus status;
    uint64_t submitted_timestamp;
    uint64_t assigned_timestamp;
    uint64_t started_timestamp;
    uint64_t completed_timestamp;
};

struct ConversionResult {
    std::string task_id;
    std::string node_id;
    bool success;
    std::vector<uint8_t> output_data;
    std::string error_message;
    uint64_t start_timestamp;
    uint64_t completion_timestamp;
    std::unordered_map<std::string, std::string> metadata;
};

struct NodeInfo {
    std::string node_id;
    std::string address;
    NodeRole role;
    NodeStatus status;
    double cpu_usage;
    double memory_usage;
    double network_usage;
    size_t active_tasks;
    size_t completed_tasks;
    std::unordered_map<std::string, double> capabilities;
    std::chrono::steady_clock::time_point last_heartbeat;
};

struct ClusterConfig {
    NodeRole node_role;
    std::string cluster_id;
    std::vector<std::string> bootstrap_nodes;
    uint16_t control_port;
    uint16_t data_port;
    uint16_t result_port;
    uint32_t heartbeat_interval_ms;
    uint32_t monitoring_interval_ms;
    uint32_t node_timeout_ms;
    uint32_t scheduling_interval_ms;
    bool auto_elect_coordinator;
    bool enable_load_balancing;
    bool enable_fault_tolerance;
    std::vector<std::string> etcd_endpoints;
    std::string consul_address;
    size_t max_concurrent_tasks;
    size_t task_timeout_seconds;
};

struct DistributedMetrics {
    size_t total_nodes;
    size_t active_nodes;
    size_t pending_tasks;
    size_t active_tasks;
    size_t completed_tasks;
    size_t failed_tasks;
    double average_cpu_usage;
    double average_memory_usage;
    double average_network_usage;
    double throughput;
    double latency;
    uint64_t bytes_processed;
    uint64_t network_bytes_sent;
    uint64_t network_bytes_received;
};

class DistributedConverter {
public:
    DistributedConverter();
    ~DistributedConverter();

    void initialize_cluster(const ClusterConfig& config);
    
    ConversionResult submit_task(const ConversionTask& task);
    
    void start();
    void stop();
    
    DistributedMetrics get_metrics() const;
    std::vector<NodeInfo> get_cluster_status() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

} 