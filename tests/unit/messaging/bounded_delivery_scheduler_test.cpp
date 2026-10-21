#include "delivery/bounded_delivery_scheduler.hpp"

#include <atomic>
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

namespace securecloud::messaging::delivery::test {
namespace {

domain::DeliveryTask make_task(domain::DeviceId device_id,
                               domain::MessagePriority priority = domain::MessagePriority::Normal,
                               std::optional<std::chrono::system_clock::time_point> expires_at = std::nullopt) {
    domain::DeliveryTask task;
    task.message_id = domain::MessageId::generate_v7();
    task.conversation_id = domain::ConversationId::generate_v7();
    task.recipient_device_id = std::move(device_id);
    task.recipient_user_id = domain::UserId("user-1");
    task.priority = priority;
    task.attempt_count = 0;
    task.accepted_at = std::chrono::system_clock::now();
    task.scheduled_at = task.accepted_at;
    task.expires_at = expires_at;
    return task;
}

TEST(BoundedDeliverySchedulerTest, DefaultConstructionAndMetrics) {
    BoundedDeliveryScheduler scheduler;

    EXPECT_EQ(scheduler.global_queue_depth(), 0u);
    EXPECT_EQ(scheduler.emergency_queue_depth(), 0u);
    EXPECT_EQ(scheduler.active_device_count(), 0u);
    EXPECT_FALSE(scheduler.is_shutdown());

    EXPECT_EQ(scheduler.config().max_global_queued_tasks, 10000u);
    EXPECT_EQ(scheduler.config().max_tasks_per_device, 50u);
    EXPECT_EQ(scheduler.config().emergency_queue_reserved_slots, 1000u);
    EXPECT_EQ(scheduler.config().fairness_quanta_per_device, 5u);
}

TEST(BoundedDeliverySchedulerTest, FifoOrderingWithinSingleDevice) {
    BoundedDeliveryScheduler scheduler;
    const domain::DeviceId dev1{"dev-1"};
    std::vector<domain::MessageId> scheduled_ids;

    for (int i = 1; i <= 5; ++i) {
        auto task = make_task(dev1);
        scheduled_ids.push_back(task.message_id);
        auto status = scheduler.schedule(task);
        EXPECT_EQ(status, SchedulerStatus::Enqueued);
    }

    EXPECT_EQ(scheduler.global_queue_depth(), 5u);
    EXPECT_EQ(scheduler.device_queue_depth(dev1), 5u);
    EXPECT_EQ(scheduler.active_device_count(), 1u);

    for (size_t i = 0; i < 5; ++i) {
        auto task = scheduler.try_dequeue();
        ASSERT_TRUE(task.has_value());
        EXPECT_EQ(task->message_id, scheduled_ids[i]);
        EXPECT_EQ(task->recipient_device_id, dev1);
    }

    EXPECT_EQ(scheduler.global_queue_depth(), 0u);
    EXPECT_EQ(scheduler.active_device_count(), 0u);
    EXPECT_FALSE(scheduler.try_dequeue().has_value());
}

TEST(BoundedDeliverySchedulerTest, EmergencyQueueStrictPreemption) {
    BoundedDeliveryScheduler scheduler;
    const domain::DeviceId dev1{"dev-1"};
    const domain::DeviceId dev2{"dev-2"};

    // Schedule 3 normal tasks for dev-1
    scheduler.schedule(make_task(dev1, domain::MessagePriority::Normal));
    scheduler.schedule(make_task(dev1, domain::MessagePriority::Normal));
    scheduler.schedule(make_task(dev1, domain::MessagePriority::Normal));

    // Schedule 1 emergency task for dev-2
    auto emerg_task = make_task(dev2, domain::MessagePriority::Emergency);
    auto emerg_id = emerg_task.message_id;
    scheduler.schedule(emerg_task);

    // Schedule 1 urgent task for dev-1
    scheduler.schedule(make_task(dev1, domain::MessagePriority::Urgent));

    EXPECT_EQ(scheduler.global_queue_depth(), 5u);
    EXPECT_EQ(scheduler.emergency_queue_depth(), 1u);

    // 1st dequeue MUST be the emergency task, preempting all others
    auto t1 = scheduler.try_dequeue();
    ASSERT_TRUE(t1.has_value());
    EXPECT_EQ(t1->message_id, emerg_id);
    EXPECT_EQ(t1->recipient_device_id, dev2);
    EXPECT_EQ(t1->priority, domain::MessagePriority::Emergency);

    // Subsequent dequeues are normal/urgent tasks for dev-1
    auto t2 = scheduler.try_dequeue();
    ASSERT_TRUE(t2.has_value());
    EXPECT_EQ(t2->recipient_device_id, dev1);

    auto t3 = scheduler.try_dequeue();
    ASSERT_TRUE(t3.has_value());
    EXPECT_EQ(t3->recipient_device_id, dev1);
}

TEST(BoundedDeliverySchedulerTest, PerDeviceCapacityLimitAndDropToDurableBackpressure) {
    DeliverySchedulerConfig cfg;
    cfg.max_tasks_per_device = 3;
    cfg.max_global_queued_tasks = 100;
    BoundedDeliveryScheduler scheduler(cfg);
    const domain::DeviceId dev_a{"dev-A"};
    const domain::DeviceId dev_b{"dev-B"};

    // Dev-A fills its allocated quota
    EXPECT_EQ(scheduler.schedule(make_task(dev_a)), SchedulerStatus::Enqueued);
    EXPECT_EQ(scheduler.schedule(make_task(dev_a)), SchedulerStatus::Enqueued);
    EXPECT_EQ(scheduler.schedule(make_task(dev_a)), SchedulerStatus::Enqueued);

    // 4th task for Dev-A is rejected with DeviceQueueFull (defers to ScyllaDB durable recovery)
    EXPECT_EQ(scheduler.schedule(make_task(dev_a)), SchedulerStatus::DeviceQueueFull);
    EXPECT_EQ(scheduler.device_queue_depth(dev_a), 3u);

    // Dev-B is isolated and unaffected by Dev-A's saturation
    EXPECT_EQ(scheduler.schedule(make_task(dev_b)), SchedulerStatus::Enqueued);
    EXPECT_EQ(scheduler.device_queue_depth(dev_b), 1u);
    EXPECT_EQ(scheduler.global_queue_depth(), 4u);
}

TEST(BoundedDeliverySchedulerTest, GlobalCapacityExhaustionAndDropToDurableBackpressure) {
    DeliverySchedulerConfig cfg;
    cfg.max_global_queued_tasks = 3;
    cfg.max_tasks_per_device = 10;
    cfg.emergency_queue_reserved_slots = 2;
    BoundedDeliveryScheduler scheduler(cfg);

    EXPECT_EQ(scheduler.schedule(make_task(domain::DeviceId("dev-1"))), SchedulerStatus::Enqueued);
    EXPECT_EQ(scheduler.schedule(make_task(domain::DeviceId("dev-2"))), SchedulerStatus::Enqueued);
    EXPECT_EQ(scheduler.schedule(make_task(domain::DeviceId("dev-3"))), SchedulerStatus::Enqueued);

    // 4th normal task exceeds global capacity
    EXPECT_EQ(scheduler.schedule(make_task(domain::DeviceId("dev-4"))), SchedulerStatus::GlobalCapacityExhausted);

    // Emergency task succeeds using reserved emergency capacity
    EXPECT_EQ(scheduler.schedule(make_task(domain::DeviceId("dev-5"), domain::MessagePriority::Emergency)),
              SchedulerStatus::Enqueued);
    EXPECT_EQ(scheduler.global_queue_depth(), 4u);
}

TEST(BoundedDeliverySchedulerTest, RoundRobinFairnessWithQuantum) {
    DeliverySchedulerConfig cfg;
    cfg.fairness_quanta_per_device = 2; // Each device gets at most 2 consecutive tasks per turn
    cfg.max_tasks_per_device = 20;
    cfg.max_global_queued_tasks = 100;
    BoundedDeliveryScheduler scheduler(cfg);

    const domain::DeviceId dev_a{"dev-A"};
    const domain::DeviceId dev_b{"dev-B"};

    // Dev-A enqueues 4 tasks
    for (int i = 1; i <= 4; ++i) {
        scheduler.schedule(make_task(dev_a));
    }

    // Dev-B enqueues 4 tasks
    for (int i = 1; i <= 4; ++i) {
        scheduler.schedule(make_task(dev_b));
    }

    // Expected dequeue pattern:
    // Dev-A (2 tasks) -> yields turn to Dev-B
    // Dev-B (2 tasks) -> yields turn to Dev-A
    // Dev-A (2 tasks) -> queue empty, removed
    // Dev-B (2 tasks) -> queue empty, removed
    std::vector<domain::DeviceId> dequeued_devices;
    for (int i = 0; i < 8; ++i) {
        auto t = scheduler.try_dequeue();
        ASSERT_TRUE(t.has_value());
        dequeued_devices.push_back(t->recipient_device_id);
    }

    const std::vector<domain::DeviceId> expected = {dev_a, dev_a, dev_b, dev_b, dev_a, dev_a, dev_b, dev_b};
    EXPECT_EQ(dequeued_devices, expected);
    EXPECT_EQ(scheduler.global_queue_depth(), 0u);
}

TEST(BoundedDeliverySchedulerTest, DrainDeviceQueueOnDisconnection) {
    BoundedDeliveryScheduler scheduler;
    const domain::DeviceId dev_a{"dev-A"};
    const domain::DeviceId dev_b{"dev-B"};

    scheduler.schedule(make_task(dev_a));
    scheduler.schedule(make_task(dev_a));
    scheduler.schedule(make_task(dev_a, domain::MessagePriority::Emergency));
    scheduler.schedule(make_task(dev_b));
    scheduler.schedule(make_task(dev_b));

    EXPECT_EQ(scheduler.global_queue_depth(), 5u);
    EXPECT_EQ(scheduler.device_queue_depth(dev_a), 2u);

    // Device A disconnects -> drain all its tasks
    auto drained = scheduler.drain_device_queue(dev_a);
    EXPECT_EQ(drained.size(), 3u);
    EXPECT_EQ(scheduler.global_queue_depth(), 2u);
    EXPECT_EQ(scheduler.device_queue_depth(dev_a), 0u);
    EXPECT_EQ(scheduler.active_device_count(), 1u);

    // Only Dev-B tasks remain
    auto t1 = scheduler.try_dequeue();
    ASSERT_TRUE(t1.has_value());
    EXPECT_EQ(t1->recipient_device_id, dev_b);

    auto t2 = scheduler.try_dequeue();
    ASSERT_TRUE(t2.has_value());
    EXPECT_EQ(t2->recipient_device_id, dev_b);

    EXPECT_FALSE(scheduler.try_dequeue().has_value());
}

TEST(BoundedDeliverySchedulerTest, ValidationRejections) {
    BoundedDeliveryScheduler scheduler;

    // Missing device ID
    auto t1 = make_task(domain::DeviceId(""));
    EXPECT_EQ(scheduler.schedule(t1), SchedulerStatus::InvalidTask);

    // Missing message ID
    auto t2 = make_task(domain::DeviceId("dev-1"));
    t2.message_id = domain::MessageId{};
    EXPECT_EQ(scheduler.schedule(t2), SchedulerStatus::InvalidTask);

    // Missing conversation ID
    auto t3 = make_task(domain::DeviceId("dev-1"));
    t3.conversation_id = domain::ConversationId{};
    EXPECT_EQ(scheduler.schedule(t3), SchedulerStatus::InvalidTask);

    // Expired task
    auto expired_time = std::chrono::system_clock::now() - std::chrono::seconds(10);
    auto t4 = make_task(domain::DeviceId("dev-1"), domain::MessagePriority::Normal, expired_time);
    EXPECT_EQ(scheduler.schedule(t4), SchedulerStatus::InvalidTask);
}

TEST(BoundedDeliverySchedulerTest, TimeoutAndTryDequeue) {
    BoundedDeliveryScheduler scheduler;

    EXPECT_FALSE(scheduler.try_dequeue().has_value());

    const auto start = std::chrono::steady_clock::now();
    auto result = scheduler.dequeue(std::chrono::milliseconds(30));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_FALSE(result.has_value());
    EXPECT_GE(elapsed, std::chrono::milliseconds(25));
}

TEST(BoundedDeliverySchedulerTest, GracefulShutdownUnblocksWorker) {
    BoundedDeliveryScheduler scheduler;
    std::atomic<bool> worker_finished{false};
    std::optional<domain::DeliveryTask> worker_result;

    std::thread worker([&] {
        worker_result = scheduler.dequeue(std::chrono::milliseconds(0)); // Block indefinitely
        worker_finished.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    EXPECT_FALSE(worker_finished.load());

    scheduler.shutdown();
    worker.join();

    EXPECT_TRUE(worker_finished.load());
    EXPECT_FALSE(worker_result.has_value());
    EXPECT_TRUE(scheduler.is_shutdown());

    // Subsequent schedule attempts rejected
    EXPECT_EQ(scheduler.schedule(make_task(domain::DeviceId("dev-1"))), SchedulerStatus::RejectedShuttingDown);
}

TEST(BoundedDeliverySchedulerTest, ConcurrentMultiProducerConsumerStressTest) {
    DeliverySchedulerConfig cfg;
    cfg.max_global_queued_tasks = 2000;
    cfg.max_tasks_per_device = 100;
    cfg.fairness_quanta_per_device = 5;
    BoundedDeliveryScheduler scheduler(cfg);

    constexpr int k_producers = 4;
    constexpr int k_consumers = 4;
    constexpr int k_tasks_per_producer = 200;

    std::atomic<bool> start_flag{false};
    std::atomic<size_t> total_enqueued{0};
    std::atomic<size_t> total_dequeued{0};

    std::vector<std::thread> producers;
    producers.reserve(k_producers);
    for (int p = 0; p < k_producers; ++p) {
        producers.emplace_back([&, p] {
            while (!start_flag.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < k_tasks_per_producer; ++i) {
                domain::DeviceId dev_id{"dev-" + std::to_string((p * 10 + i) % 20)};
                auto res = scheduler.schedule(make_task(dev_id));
                if (res == SchedulerStatus::Enqueued) {
                    total_enqueued.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    std::vector<std::thread> consumers;
    consumers.reserve(k_consumers);
    for (int c = 0; c < k_consumers; ++c) {
        consumers.emplace_back([&] {
            while (!start_flag.load(std::memory_order_relaxed)) {
                std::this_thread::yield();
            }
            while (true) {
                auto task = scheduler.dequeue(std::chrono::milliseconds(50));
                if (task.has_value()) {
                    total_dequeued.fetch_add(1, std::memory_order_relaxed);
                } else if (scheduler.is_shutdown() && scheduler.global_queue_depth() == 0) {
                    break;
                }
            }
        });
    }

    start_flag.store(true);

    for (auto& t : producers) {
        t.join();
    }

    // Wait for consumers to drain queue
    while (scheduler.global_queue_depth() > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    scheduler.shutdown();

    for (auto& t : consumers) {
        t.join();
    }

    EXPECT_GT(total_enqueued.load(), 0u);
    EXPECT_EQ(total_enqueued.load(), total_dequeued.load());
    EXPECT_EQ(scheduler.global_queue_depth(), 0u);
}

} // namespace
} // namespace securecloud::messaging::delivery::test
