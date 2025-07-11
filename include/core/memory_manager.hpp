#pragma once

#include <memory>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <vector>
#include <algorithm>
#include <concepts>
#include <span>
#include <expected>

namespace converter::core {

template<typename T>
concept Alignable = std::is_standard_layout_v<T> && std::is_trivial_v<T>;

class MemoryPool {
public:
    explicit MemoryPool(std::size_t block_size, std::size_t initial_blocks = 16);
    ~MemoryPool();
    
    void* allocate(std::size_t size, std::size_t alignment = alignof(std::max_align_t));
    void deallocate(void* ptr, std::size_t size);
    
    std::size_t get_total_size() const;
    std::size_t get_used_size() const;
    std::size_t get_free_size() const;
    
    void defragment();
    void clear();
    
private:
    struct Block {
        void* data;
        std::size_t size;
        bool is_free;
        Block* next;
    };
    
    std::size_t block_size_;
    std::vector<std::unique_ptr<uint8_t[]>> pools_;
    std::atomic<Block*> free_list_;
    std::mutex mutex_;
    std::atomic<std::size_t> total_size_;
    std::atomic<std::size_t> used_size_;
};

template<typename T>
class ObjectPool {
public:
    explicit ObjectPool(std::size_t initial_size = 64);
    ~ObjectPool();
    
    template<typename... Args>
    std::unique_ptr<T> acquire(Args&&... args);
    
    void release(std::unique_ptr<T> obj);
    
    std::size_t get_pool_size() const;
    std::size_t get_available_count() const;
    
    void reserve(std::size_t count);
    void shrink_to_fit();
    
private:
    std::vector<std::unique_ptr<T>> pool_;
    std::mutex mutex_;
    std::atomic<std::size_t> available_count_;
};

class MemoryManager {
public:
    static MemoryManager& instance();
    
    void* allocate(std::size_t size, std::size_t alignment = alignof(std::max_align_t));
    void deallocate(void* ptr, std::size_t size);
    
    template<Alignable T>
    T* allocate_aligned(std::size_t count = 1);
    
    template<Alignable T>
    void deallocate_aligned(T* ptr, std::size_t count = 1);
    
    std::expected<void*, std::error_code> allocate_huge(std::size_t size);
    std::expected<void, std::error_code> deallocate_huge(void* ptr, std::size_t size);
    
    void set_memory_limit(std::size_t limit);
    std::size_t get_memory_limit() const;
    
    std::size_t get_total_allocated() const;
    std::size_t get_peak_allocation() const;
    
    void enable_tracking(bool enable);
    bool is_tracking_enabled() const;
    
    std::unordered_map<std::string, std::size_t> get_allocation_stats() const;
    
    void enable_debugging(bool enable);
    bool is_debugging_enabled() const;
    
    std::expected<void, std::error_code> check_memory_integrity();
    
    void register_allocation_callback(std::function<void(std::size_t)> callback);
    void register_deallocation_callback(std::function<void(std::size_t)> callback);
    
    void force_garbage_collection();
    void optimize_memory_usage();
    
private:
    MemoryManager();
    ~MemoryManager();
    
    struct AllocationInfo {
        std::size_t size;
        std::string file;
        int line;
        std::thread::id thread_id;
        std::chrono::system_clock::time_point timestamp;
    };
    
    std::unordered_map<void*, AllocationInfo> allocations_;
    std::vector<std::unique_ptr<MemoryPool>> pools_;
    std::mutex mutex_;
    std::atomic<std::size_t> memory_limit_;
    std::atomic<std::size_t> total_allocated_;
    std::atomic<std::size_t> peak_allocation_;
    std::atomic<bool> tracking_enabled_;
    std::atomic<bool> debugging_enabled_;
    std::vector<std::function<void(std::size_t)>> allocation_callbacks_;
    std::vector<std::function<void(std::size_t)>> deallocation_callbacks_;
};

template<typename T>
class UniquePtr {
public:
    UniquePtr() = default;
    explicit UniquePtr(T* ptr) : ptr_(ptr) {}
    
    UniquePtr(const UniquePtr&) = delete;
    UniquePtr& operator=(const UniquePtr&) = delete;
    
    UniquePtr(UniquePtr&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }
    
    UniquePtr& operator=(UniquePtr&& other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }
    
    ~UniquePtr() {
        reset();
    }
    
    T* get() const { return ptr_; }
    T& operator*() const { return *ptr_; }
    T* operator->() const { return ptr_; }
    
    explicit operator bool() const { return ptr_ != nullptr; }
    
    T* release() {
        T* temp = ptr_;
        ptr_ = nullptr;
        return temp;
    }
    
    void reset(T* ptr = nullptr) {
        if (ptr_) {
            MemoryManager::instance().deallocate_aligned(ptr_);
        }
        ptr_ = ptr;
    }
    
private:
    T* ptr_ = nullptr;
};

template<typename T>
class SharedPtr {
public:
    SharedPtr() = default;
    explicit SharedPtr(T* ptr) : ptr_(ptr), ref_count_(ptr ? new std::atomic<std::size_t>(1) : nullptr) {}
    
    SharedPtr(const SharedPtr& other) : ptr_(other.ptr_), ref_count_(other.ref_count_) {
        if (ref_count_) {
            ref_count_->fetch_add(1);
        }
    }
    
    SharedPtr& operator=(const SharedPtr& other) {
        if (this != &other) {
            release();
            ptr_ = other.ptr_;
            ref_count_ = other.ref_count_;
            if (ref_count_) {
                ref_count_->fetch_add(1);
            }
        }
        return *this;
    }
    
    SharedPtr(SharedPtr&& other) noexcept : ptr_(other.ptr_), ref_count_(other.ref_count_) {
        other.ptr_ = nullptr;
        other.ref_count_ = nullptr;
    }
    
    SharedPtr& operator=(SharedPtr&& other) noexcept {
        if (this != &other) {
            release();
            ptr_ = other.ptr_;
            ref_count_ = other.ref_count_;
            other.ptr_ = nullptr;
            other.ref_count_ = nullptr;
        }
        return *this;
    }
    
    ~SharedPtr() {
        release();
    }
    
    T* get() const { return ptr_; }
    T& operator*() const { return *ptr_; }
    T* operator->() const { return ptr_; }
    
    explicit operator bool() const { return ptr_ != nullptr; }
    
    std::size_t use_count() const {
        return ref_count_ ? ref_count_->load() : 0;
    }
    
    bool unique() const {
        return use_count() == 1;
    }
    
    void reset(T* ptr = nullptr) {
        release();
        ptr_ = ptr;
        ref_count_ = ptr ? new std::atomic<std::size_t>(1) : nullptr;
    }
    
private:
    void release() {
        if (ref_count_ && ref_count_->fetch_sub(1) == 1) {
            MemoryManager::instance().deallocate_aligned(ptr_);
            delete ref_count_;
        }
        ptr_ = nullptr;
        ref_count_ = nullptr;
    }
    
    T* ptr_ = nullptr;
    std::atomic<std::size_t>* ref_count_ = nullptr;
};

template<typename T, typename... Args>
UniquePtr<T> make_unique(Args&&... args) {
    T* ptr = MemoryManager::instance().allocate_aligned<T>();
    try {
        new (ptr) T(std::forward<Args>(args)...);
        return UniquePtr<T>(ptr);
    } catch (...) {
        MemoryManager::instance().deallocate_aligned(ptr);
        throw;
    }
}

template<typename T, typename... Args>
SharedPtr<T> make_shared(Args&&... args) {
    T* ptr = MemoryManager::instance().allocate_aligned<T>();
    try {
        new (ptr) T(std::forward<Args>(args)...);
        return SharedPtr<T>(ptr);
    } catch (...) {
        MemoryManager::instance().deallocate_aligned(ptr);
        throw;
    }
}

} 