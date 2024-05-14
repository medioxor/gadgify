#ifndef GADGIFY_THREADPOOL_H
#define GADGIFY_THREADPOOL_H

#include <cstdint>
#include <thread>
#include <vector>
#include <deque>
#include <functional>
#include <mutex>
#include <condition_variable>

class ThreadPool {
public:
    explicit ThreadPool(uint32_t threads = std::thread::hardware_concurrency());
    void Enqueue(const std::function<void()>& task);
    void Wait();
    virtual ~ThreadPool();
private:
    void Thread();

    std::vector<std::thread> threads_;
    std::deque<std::function<void()>> taskQueue_;
    std::mutex taskQueueMutex_;
    std::condition_variable newTaskCondition_;
    std::condition_variable finishedTaskCondition_;
    std::atomic_uint runningTasks_;
    std::atomic_bool stopThreads_{false};
};


#endif //GADGIFY_THREADPOOL_H
