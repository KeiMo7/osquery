/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/sql/table_publication.h>
#include <osquery/sql/virtual_table.h>

namespace osquery {

namespace {

using namespace std::chrono_literals;

TableColumns markerColumns() {
  return {std::make_tuple("marker", TEXT_TYPE, ColumnOptions::DEFAULT)};
}

class MarkerTablePlugin : public TablePlugin {
 public:
  explicit MarkerTablePlugin(std::string marker, std::size_t row_count = 2)
      : marker_(std::move(marker)), row_count_(row_count) {}

  TableColumns columns() const override {
    return markerColumns();
  }

  TableRows generate(QueryContext&) override {
    TableRows rows;
    for (std::size_t i = 0; i < row_count_; ++i) {
      rows.push_back(make_table_row({{"marker", marker_}}));
    }
    return rows;
  }

 private:
  std::string marker_;
  std::size_t row_count_;
};

class BlockingTablePlugin : public TablePlugin {
 public:
  TableColumns columns() const override {
    return {std::make_tuple("id", INTEGER_TYPE, ColumnOptions::DEFAULT)};
  }

  TableRows generate(QueryContext&) override {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      entered_ = true;
    }
    entered_cv_.notify_all();

    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [this] { return !blocked_; });

    TableRows rows;
    rows.push_back(make_table_row({{"id", "1"}}));
    return rows;
  }

  bool waitForEntered(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    return entered_cv_.wait_for(lock, timeout, [this] { return entered_; });
  }

  void release() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      blocked_ = false;
    }
    cv_.notify_all();
  }

 private:
  std::mutex mutex_;
  std::condition_variable cv_;
  std::condition_variable entered_cv_;
  bool blocked_{true};
  bool entered_{false};
};

TableEntryPtr makeEntry(const std::string& name,
                        const std::string& marker,
                        const std::string& source = "unit-source") {
  auto plugin = std::make_shared<MarkerTablePlugin>(marker);
  auto entry = std::make_shared<TableEntry>(
      name, plugin, markerColumns(), TableAttributes::NONE, 0, source);
  entry->query = "SELECT marker FROM source_table";
  entry->sql = entry->query;
  entry->path = "/tmp/osquery-table-publication-test.db";
  entry->requires_sqlite_source = false;
  return entry;
}

Status publishOne(const std::string& name,
                  const std::string& marker,
                  const std::string& hash,
                  const std::string& source = "unit-source") {
  TablePublicationStats stats;
  std::vector<TableEntryPtr> desired{makeEntry(name, marker, source)};
  return TablePublicationRegistry::publish(desired, hash, stats);
}

} // namespace

class TablePublicationTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
    TablePublicationRegistry::resetForTesting();
  }

  void TearDown() override {
    TablePublicationRegistry::resetForTesting();
  }
};

TEST_F(TablePublicationTests, ConcurrentReadsObserveCompleteGenerations) {
  constexpr const char* kTableName = "publication_concurrent_table";
  constexpr int kIterations = 200;

  auto first_status = publishOne(kTableName, "A", "concurrent-hash-0");
  ASSERT_TRUE(first_status.ok()) << first_status.getMessage();

  std::atomic<bool> stop{false};
  std::atomic<int> next_hash{1};
  std::mutex error_mutex;
  std::string first_error;

  auto record_error = [&](const std::string& message) {
    std::lock_guard<std::mutex> lock(error_mutex);
    if (first_error.empty()) {
      first_error = message;
    }
  };

  std::vector<std::thread> readers;
  for (int reader = 0; reader < 8; ++reader) {
    readers.emplace_back([&, reader] {
      auto dbc = SQLiteDBManager::getUnique();
      if (!dbc) {
        record_error("reader " + std::to_string(reader) + " has no database");
        return;
      }

      for (int i = 0; i < kIterations && !stop.load(); ++i) {
        QueryData rows;
        auto status = queryInternal(
            "SELECT marker FROM " + std::string(kTableName), rows, dbc);
        if (!status.ok()) {
          record_error("query failed: " + status.getMessage());
          return;
        }

        if (rows.empty()) {
          record_error("query returned no rows");
          return;
        }

        const auto& expected = rows.front().at("marker");
        if (expected != "A" && expected != "B") {
          record_error("unexpected marker: " + expected);
          return;
        }

        for (const auto& row : rows) {
          auto it = row.find("marker");
          if (it == row.end() || it->second != expected) {
            record_error("result mixed generation markers");
            return;
          }
        }
      }
    });
  }

  for (int i = 0; i < 120; ++i) {
    std::string marker = (i % 2 == 0) ? "B" : "A";
    auto status = publishOne(
        kTableName, marker, "concurrent-hash-" + std::to_string(next_hash++));
    ASSERT_TRUE(status.ok()) << status.getMessage();
    std::this_thread::sleep_for(100us);
  }

  stop.store(true);
  for (auto& thread : readers) {
    thread.join();
  }

  ASSERT_TRUE(first_error.empty()) << first_error;
}

TEST_F(TablePublicationTests, RetireWaitsForActiveQueryThenRemovesTable) {
  constexpr const char* kTableName = "publication_retire_table";

  auto plugin = std::make_shared<BlockingTablePlugin>();
  auto entry = std::make_shared<TableEntry>(
      kTableName,
      plugin,
      TableColumns{std::make_tuple("id", INTEGER_TYPE, ColumnOptions::DEFAULT)},
      TableAttributes::NONE,
      0,
      "retire-source");
  entry->query = "SELECT id";
  entry->path = "/tmp/retire.db";

  TablePublicationStats publish_stats;
  std::vector<TableEntryPtr> desired{entry};
  auto publish_status = TablePublicationRegistry::publish(
      desired, "retire-hash-1", publish_stats);
  ASSERT_TRUE(publish_status.ok()) << publish_status.getMessage();

  auto dbc = SQLiteDBManager::getUnique();
  ASSERT_NE(dbc, nullptr);

  QueryData rows;
  std::mutex query_mutex;
  std::unique_lock<std::mutex> query_lock(query_mutex, std::defer_lock);
  auto query_result = std::async(std::launch::async, [&] {
    return queryInternal("SELECT id FROM publication_retire_table", rows, dbc);
  });

  ASSERT_TRUE(plugin->waitForEntered(5s));

  std::vector<TableEntryPtr> empty;
  TablePublicationStats delete_stats;
  auto delete_status =
      TablePublicationRegistry::publish(empty,
                                        std::vector<std::string>{kTableName},
                                        "retire-delete-hash",
                                        delete_stats);
  ASSERT_TRUE(delete_status.ok()) << delete_status.getMessage();
  ASSERT_EQ(TablePublicationRegistry::snapshot()->find(kTableName), nullptr);

  auto retire_result = std::async(std::launch::async, [] {
    return TablePublicationRegistry::retire(kTableName, 5s);
  });

  ASSERT_NE(retire_result.wait_for(100ms), std::future_status::ready);

  plugin->release();
  auto query_status = query_result.get();
  EXPECT_TRUE(query_status.ok()) << query_status.getMessage();

  EXPECT_EQ(retire_result.wait_for(5s), std::future_status::ready);
  auto retire_status = retire_result.get();
  EXPECT_TRUE(retire_status.ok()) << retire_status.getMessage();

  auto new_db = SQLiteDBManager::getUnique();
  QueryData missing_rows;
  auto missing_status = queryInternal(
      "SELECT * FROM publication_retire_table", missing_rows, new_db);
  EXPECT_FALSE(missing_status.ok());
}

TEST_F(TablePublicationTests, RollbackKeepsGenerationAndOldDefinition) {
  constexpr const char* kOldTable = "publication_rollback_old";
  ASSERT_TRUE(publishOne(kOldTable, "OLD", "rollback-old-hash").ok());
  auto old_snapshot = TablePublicationRegistry::snapshot();
  ASSERT_EQ(old_snapshot->generation, 1U);

  std::vector<TableEntryPtr> bad_desired;
  auto bad = makeEntry("publication_bad_columns", "X");
  for (int i = 0; i < 65; ++i) {
    bad->columns.emplace_back(
        "c" + std::to_string(i), TEXT_TYPE, ColumnOptions::DEFAULT);
  }
  bad_desired.push_back(bad);

  TablePublicationStats bad_stats;
  auto bad_status = TablePublicationRegistry::publish(
      bad_desired, "rollback-bad-hash", bad_stats);
  EXPECT_NE(bad_status.getCode(), 0);
  EXPECT_EQ(TablePublicationRegistry::snapshot()->generation, 1U);

  class CoreConflictPlugin : public TablePlugin {
   public:
    TableColumns columns() const override {
      return {std::make_tuple("x", TEXT_TYPE, ColumnOptions::DEFAULT)};
    }
  };

  constexpr const char* kConflictName = "publication_core_conflict";
  RegistryFactory::get().registry("table")->add(
      kConflictName, std::make_shared<CoreConflictPlugin>());

  auto conflict_entry = makeEntry(kConflictName, "CONFLICT");
  TablePublicationStats conflict_stats;
  auto conflict_status = TablePublicationRegistry::publish(
      std::vector<TableEntryPtr>{conflict_entry},
      "rollback-conflict-hash",
      conflict_stats);
  EXPECT_NE(conflict_status.getCode(), 0);
  EXPECT_EQ(TablePublicationRegistry::snapshot()->generation, 1U);

  auto dbc = SQLiteDBManager::getUnique();
  QueryData rows;
  auto status =
      queryInternal("SELECT marker FROM publication_rollback_old", rows, dbc);
  ASSERT_TRUE(status.ok()) << status.getMessage();
  ASSERT_EQ(rows.size(), 2U);
  for (const auto& row : rows) {
    EXPECT_EQ(row.at("marker"), "OLD");
  }
}

TEST_F(TablePublicationTests, DegradedEntryPreservesPreviousInstance) {
  auto legacy = std::make_shared<TableSnapshot>();
  legacy->generation = 7;
  legacy->content_hash = "legacy";
  auto old_bad_entry = makeEntry("Bad-Name", "LEGACY");
  legacy->tables["Bad-Name"] = old_bad_entry;
  TablePublicationRegistry::seedSnapshotForTesting(
      std::const_pointer_cast<const TableSnapshot>(legacy));

  auto valid = makeEntry("publication_degraded_valid", "OK");
  auto invalid = makeEntry("Bad-Name", "NEW");

  TablePublicationStats stats;
  auto status = TablePublicationRegistry::publish(
      std::vector<TableEntryPtr>{valid, invalid}, "degraded-hash", stats);
  EXPECT_TRUE(status.ok()) << status.getMessage();
  EXPECT_EQ(stats.published, 1U);
  EXPECT_EQ(stats.skipped, 1U);
  ASSERT_NE(stats.skip_reasons.find("Bad-Name"), stats.skip_reasons.end());

  auto snapshot = TablePublicationRegistry::snapshot();
  EXPECT_EQ(snapshot->generation, 8U);
  auto preserved = snapshot->find("Bad-Name");
  ASSERT_NE(preserved, nullptr);
  EXPECT_EQ(preserved.get(), old_bad_entry.get());
  EXPECT_NE(snapshot->find("publication_degraded_valid"), nullptr);
}

TEST_F(TablePublicationTests, ValidationBoundaries) {
  auto valid_name = std::string("a") + std::string(63, 'b');
  auto entry = makeEntry(valid_name, "X");
  std::string reason;
  EXPECT_TRUE(TablePublicationRegistry::validate(*entry, reason).ok())
      << reason;

  auto too_long = makeEntry("a" + std::string(64, 'b'), "X");
  auto status = TablePublicationRegistry::validate(*too_long, reason);
  EXPECT_FALSE(status.ok());
  EXPECT_NE(reason.find("64"), std::string::npos) << reason;

  auto uppercase = makeEntry("Bad_Name", "X");
  status = TablePublicationRegistry::validate(*uppercase, reason);
  EXPECT_FALSE(status.ok());
  EXPECT_NE(reason.find("lowercase"), std::string::npos) << reason;

  auto semicolon = makeEntry("publication_validate_semicolon", "X");
  semicolon->sql = "SELECT 1;";
  status = TablePublicationRegistry::validate(*semicolon, reason);
  EXPECT_FALSE(status.ok());
  EXPECT_NE(reason.find("semicolon"), std::string::npos) << reason;

  auto with_query = makeEntry("publication_validate_with", "X");
  with_query->sql = "WITH x AS (SELECT 1 AS one) SELECT * FROM x";
  EXPECT_TRUE(TablePublicationRegistry::validate(*with_query, reason).ok())
      << reason;

  auto attach = makeEntry("publication_validate_attach", "X");
  attach->sql = "ATTACH DATABASE ':memory:' AS evil";
  status = TablePublicationRegistry::validate(*attach, reason);
  EXPECT_FALSE(status.ok());
  EXPECT_NE(reason.find("ATTACH"), std::string::npos) << reason;

  auto relative_path = makeEntry("publication_validate_relative", "X");
  relative_path->path = "relative/path.db";
  status = TablePublicationRegistry::validate(*relative_path, reason);
  EXPECT_FALSE(status.ok());
  EXPECT_NE(reason.find("absolute"), std::string::npos) << reason;

  auto parent_path = makeEntry("publication_validate_parent", "X");
  parent_path->path = "/tmp/../secret.db";
  status = TablePublicationRegistry::validate(*parent_path, reason);
  EXPECT_FALSE(status.ok());
  EXPECT_NE(reason.find(".."), std::string::npos) << reason;
}

TEST_F(TablePublicationTests, IdenticalHashIsIdempotent) {
  std::vector<TableEntryPtr> desired{makeEntry("publication_idempotent", "A")};
  TablePublicationStats first_stats;
  auto first =
      TablePublicationRegistry::publish(desired, "same-hash", first_stats);
  ASSERT_TRUE(first.ok()) << first.getMessage();
  auto first_snapshot = TablePublicationRegistry::snapshot();
  auto generation = first_snapshot->generation;

  TablePublicationStats second_stats;
  auto second =
      TablePublicationRegistry::publish(desired, "same-hash", second_stats);
  EXPECT_EQ(second.getCode(), 2);
  auto second_snapshot = TablePublicationRegistry::snapshot();
  EXPECT_EQ(second_snapshot.get(), first_snapshot.get());
  EXPECT_EQ(second_snapshot->generation, generation);
}

TEST_F(TablePublicationTests, DrainTimesOutAndThenSucceeds) {
  constexpr const char* kName = "publication_drain_cursor";
  TablePublicationRegistry::acquireCursor(kName);

  auto timeout = TablePublicationRegistry::drain(50ms);
  EXPECT_FALSE(timeout.ok());

  TablePublicationRegistry::releaseCursor(kName);
  auto success = TablePublicationRegistry::drain(500ms);
  EXPECT_TRUE(success.ok()) << success.getMessage();
}

} // namespace osquery
