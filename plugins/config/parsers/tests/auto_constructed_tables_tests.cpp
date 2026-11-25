/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <sqlite3.h>

#include <boost/filesystem.hpp>

#include <osquery/config/config.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/sql/table_publication.h>

namespace fs = boost::filesystem;

namespace osquery {

class AutoConstructedTablesTests : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
    TablePublicationRegistry::resetForTesting();

    db_path_ =
        fs::path(fs::temp_directory_path() / "osquery_atc_integration_test.db")
            .generic_string();
    fs::remove(db_path_);
    createSourceDatabase();
  }

  void TearDown() override {
    TablePublicationRegistry::resetForTesting();
    fs::remove(db_path_);
  }

  void createSourceDatabase() {
    sqlite3* db = nullptr;
    ASSERT_EQ(sqlite3_open(db_path_.c_str(), &db), SQLITE_OK);

    const char* sql =
        "CREATE TABLE source_a(label TEXT);"
        "INSERT INTO source_a VALUES ('A1'), ('A2');"
        "CREATE TABLE source_b(label TEXT);"
        "INSERT INTO source_b VALUES ('B1'), ('B2');";
    char* error = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &error);
    if (rc != SQLITE_OK) {
      FAIL() << "source database setup failed: "
             << (error != nullptr ? error : "unknown");
    }
    sqlite3_free(error);
    sqlite3_close(db);
  }

  QueryData query(const std::string& sql, Status& status) {
    auto instance = SQLiteDBManager::getUnique();
    QueryData rows;
    status = queryInternal(sql, rows, instance);
    return rows;
  }

  std::string db_path_;
};

TEST_F(AutoConstructedTablesTests, ConfigUpdatePublishesAndSwapsTables) {
  auto& config = Config::get();
  std::map<std::string, std::string> first_config;
  first_config["atc-integration-source"] =
      "{\"auto_table_construction\":{"
      "\"atc_integration_a\":{"
      "\"query\":\"SELECT label FROM source_a\","
      "\"path\":\"" +
      db_path_ +
      "\","
      "\"columns\":[\"label\"]}}}";

  auto update_status = config.update(first_config);
  ASSERT_TRUE(update_status.ok()) << update_status.getMessage();

  Status query_status;
  auto rows =
      query("SELECT label FROM atc_integration_a ORDER BY label", query_status);
  ASSERT_TRUE(query_status.ok()) << query_status.getMessage();
  ASSERT_EQ(rows.size(), 2U);
  EXPECT_EQ(rows[0].at("label"), "A1");
  EXPECT_EQ(rows[1].at("label"), "A2");

  std::map<std::string, std::string> second_config;
  second_config["atc-integration-source"] =
      "{\"auto_table_construction\":{"
      "\"atc_integration_b\":{"
      "\"query\":\"SELECT label FROM source_b\","
      "\"path\":\"" +
      db_path_ +
      "\","
      "\"columns\":[\"label\"]}}}";

  update_status = config.update(second_config);
  ASSERT_TRUE(update_status.ok()) << update_status.getMessage();

  rows =
      query("SELECT label FROM atc_integration_b ORDER BY label", query_status);
  ASSERT_TRUE(query_status.ok()) << query_status.getMessage();
  ASSERT_EQ(rows.size(), 2U);
  EXPECT_EQ(rows[0].at("label"), "B1");
  EXPECT_EQ(rows[1].at("label"), "B2");

  QueryData old_rows;
  auto old_instance = SQLiteDBManager::getUnique();
  auto old_status =
      queryInternal("SELECT * FROM atc_integration_a", old_rows, old_instance);
  EXPECT_FALSE(old_status.ok());

  std::string atc_value;
  EXPECT_TRUE(
      getDatabaseValue(kPersistentSettings, "atc.atc_integration_b", atc_value)
          .ok());
  EXPECT_FALSE(
      getDatabaseValue(kPersistentSettings, "atc.atc_integration_a", atc_value)
          .ok());
}

} // namespace osquery
