#pragma once

#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <atomic>
#include <memory>
#include <concepts>
#include <coroutine>
#include <expected>

namespace converter::core {

template<typename T>
concept Callable = std::is_invocable_v<T>;

enum class TaskPriority : uint8_t {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3
};

template<typename T>
struct Task {
    std::function<T()> function;
    TaskPriority priority;
    std::chrono::system_clock::time_point deadline;
    std::string name;
    std::size_t task_id;
    
    bool operator<(const Task& other) const {
        if (priority != other.priority) {
            return priority < other.priority;
        }
        return deadline > other.deadline;
    }
};

class ThreadPool {
public:
    explicit ThreadPool(std::size_t thread_count = std::thread::hardware_concurrency());
    ~ThreadPool();
    
    template<Callable F, typename... Args>
    auto submit(F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>>;
    
    template<Callable F, typename... Args>
    auto submit_with_priority(TaskPriority priority, F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>>;
    
    template<Callable F, typename... Args>
    auto submit_with_deadline(std::chrono::system_clock::time_point deadline, F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>>;
    
    template<Callable F, typename... Args>
    auto submit_named(const std::string& name, F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>>;
    
    template<typename Iterator, Callable F>
    auto parallel_for(Iterator first, Iterator last, F&& f) -> std::vector<std::future<void>>;
    
    template<typename Container, Callable F>
    auto parallel_for_each(Container&& container, F&& f) -> std::vector<std::future<void>>;
    
    template<typename T, Callable F>
    auto parallel_transform(const std::vector<T>& input, F&& f) -> std::future<std::vector<std::invoke_result_t<F, T>>>;
    
    template<typename T, Callable F, Callable Reducer>
    auto parallel_reduce(const std::vector<T>& input, F&& mapper, Reducer&& reducer) -> std::future<std::invoke_result_t<Reducer, std::invoke_result_t<F, T>, std::invoke_result_t<F, T>>>;
    
    void resize(std::size_t new_size);
    std::size_t size() const;
    
    std::size_t get_active_tasks() const;
    std::size_t get_pending_tasks() const;
    
    void wait_for_all();
    void cancel_all();
    
    void set_thread_affinity(const std::vector<std::size_t>& cpu_ids);
    void set_thread_priority(int priority);
    
    std::expected<void, std::error_code> pause();
    std::expected<void, std::error_code> resume();
    bool is_paused() const;
    
    void enable_task_profiling(bool enable);
    bool is_task_profiling_enabled() const;
    
    std::unordered_map<std::string, std::chrono::milliseconds> get_task_statistics() const;
    
    void set_exception_handler(std::function<void(std::exception_ptr)> handler);
    
private:
    void worker_thread();
    void profiler_thread();
    
    std::vector<std::thread> workers_;
    std::priority_queue<Task<void>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_;
    std::atomic<bool> paused_;
    std::atomic<std::size_t> active_tasks_;
    std::atomic<std::size_t> next_task_id_;
    
    std::atomic<bool> profiling_enabled_;
    std::thread profiler_thread_;
    std::unordered_map<std::string, std::chrono::milliseconds> task_statistics_;
    std::mutex statistics_mutex_;
    
    std::function<void(std::exception_ptr)> exception_handler_;
    std::mutex exception_mutex_;
};

class WorkStealingThreadPool {
public:
    explicit WorkStealingThreadPool(std::size_t thread_count = std::thread::hardware_concurrency());
    ~WorkStealingThreadPool();
    
    template<Callable F, typename... Args>
    auto submit(F&& f, Args&&... args) -> std::future<std::invoke_result_t<F, Args...>>;
    
    template<typename Iterator, Callable F>
    auto parallel_for(Iterator first, Iterator last, F&& f) -> std::vector<std::future<void>>;
    
    void resize(std::size_t new_size);
    std::size_t size() const;
    
    std::size_t get_total_tasks() const;
    std::size_t get_stolen_tasks() const;
    
    void enable_work_stealing(bool enable);
    bool is_work_stealing_enabled() const;
    
private:
    class WorkStealingQueue {
    public:
        void push(std::function<void()> task);
        std::optional<std::function<void()>> pop();
        std::optional<std::function<void()>> steal();
        std::size_t size() const;
        
    private:
        std::deque<std::function<void()>> queue_;
        mutable std::mutex mutex_;
    };
    
    void worker_thread(std::size_t worker_id);
    std::optional<std::function<void()>> try_steal_task(std::size_t worker_id);
    
    std::vector<std::thread> workers_;
    std::vector<std::unique_ptr<WorkStealingQueue>> queues_;
    std::atomic<bool> stop_;
    std::atomic<std::size_t> total_tasks_;
    std::atomic<std::size_t> stolen_tasks_;
    std::atomic<bool> work_stealing_enabled_;
};

class CoroutineScheduler {
public:
    struct Task {
        std::coroutine_handle<> handle;
        TaskPriority priority;
        std::chrono::system_clock::time_point deadline;
        
        bool operator<(const Task& other) const {
            if (priority != other.priority) {
                return priority < other.priority;
            }
            return deadline > other.deadline;
        }
    };
    
    explicit CoroutineScheduler(std::size_t thread_count = std::thread::hardware_concurrency());
    ~CoroutineScheduler();
    
    void schedule(std::coroutine_handle<> handle, TaskPriority priority = TaskPriority::Normal);
    void schedule_with_deadline(std::coroutine_handle<> handle, std::chrono::system_clock::time_point deadline);
    
    void yield();
    void sleep_for(std::chrono::milliseconds duration);
    void sleep_until(std::chrono::system_clock::time_point time_point);
    
    std::size_t get_active_coroutines() const;
    std::size_t get_pending_coroutines() const;
    
    void shutdown();
    
private:
    void scheduler_thread();
    
    std::vector<std::thread> workers_;
    std::priority_queue<Task> ready_queue_;
    std::vector<std::pair<std::chrono::system_clock::time_point, std::coroutine_handle<>>> sleeping_tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::atomic<bool> stop_;
    std::atomic<std::size_t> active_coroutines_;
};

template<typename T>
class TaskFuture {
public:
    TaskFuture() = default;
    explicit TaskFuture(std::future<T> future) : future_(std::move(future)) {}
    
    T get() { return future_.get(); }
    
    bool valid() const { return future_.valid(); }
    
    std::future_status wait_for(const std::chrono::milliseconds& timeout) {
        return future_.wait_for(timeout);
    }
    
    std::future_status wait_until(const std::chrono::system_clock::time_point& timeout) {
        return future_.wait_until(timeout);
    }
    
    void wait() { future_.wait(); }
    
    bool is_ready() const {
        return future_.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
    }
    
    template<Callable F>
    auto then(F&& f) -> TaskFuture<std::invoke_result_t<F, T>>;
    
    template<Callable F>
    auto catch_error(F&& f) -> TaskFuture<T>;
    
private:
    std::future<T> future_;
};

template<typename... Futures>
auto when_all(Futures&&... futures) -> TaskFuture<std::tuple<typename std::decay_t<Futures>::value_type...>>;

template<typename... Futures>
auto when_any(Futures&&... futures) -> TaskFuture<std::variant<typename std::decay_t<Futures>::value_type...>>;

template<typename T>
auto when_all(std::vector<TaskFuture<T>>&& futures) -> TaskFuture<std::vector<T>>;

template<typename T>
auto when_any(std::vector<TaskFuture<T>>&& futures) -> TaskFuture<T>;

} 