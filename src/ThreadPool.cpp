#include "ThreadPool.h"

ThreadPool::ThreadPool(uint32_t threads) {
    for (int i = 0; i < threads; i++)
    {
        threads_.emplace_back(std::bind(&ThreadPool::Thread, this));
    }
}

void ThreadPool::Thread() {
    while (!stopThreads_)
    {
        std::unique_lock<std::mutex> latch(taskQueueMutex_);
        // wait here for newTaskCondition_ to be notified via ThreadPool::Enqueue
        newTaskCondition_.wait(latch, [&](){
            return !taskQueue_.empty() || stopThreads_;
        });
        if (!taskQueue_.empty())
        {
            runningTasks_++;
            auto task = taskQueue_.front();
            taskQueue_.pop_front();
            latch.unlock();
            task();
            latch.lock();
            runningTasks_--;
            finishedTaskCondition_.notify_one();
        }
        else if (stopThreads_)
        {
            break;
        }
    }
}

void ThreadPool::Wait() {
    std::unique_lock<std::mutex> lock(taskQueueMutex_);
    finishedTaskCondition_.wait(lock, [&](){
        return taskQueue_.empty() && (runningTasks_ == 0);
    });
}

ThreadPool::~ThreadPool() {
    stopThreads_ = true;
    newTaskCondition_.notify_all();
    for (auto& thread : threads_)
        thread.join();
}

void ThreadPool::Enqueue(const std::function<void(void)>& task) {
    // lock the task queue
    std::unique_lock<std::mutex> lock(taskQueueMutex_);
    // place a job on it
    taskQueue_.emplace_back(task);
    // notify any on of the threads waiting on newTaskCondition_ to start a task
    newTaskCondition_.notify_one();
}
