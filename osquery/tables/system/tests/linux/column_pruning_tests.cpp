/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>
#include <fstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/sql/virtual_table.h>

#include <boost/filesystem.hpp>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace osquery {

DECLARE_bool(enable_column_pruning);

namespace tables {
// Defined in the table implementations linked into this test.
TableRows genProcesses(QueryContext& context);
QueryData genFile(QueryContext& context);
QueryData genOpenSockets(QueryContext& context);
} // namespace tables

namespace {

namespace fs = boost::filesystem;

// Minimal TablePlugin wrappers around the real table implementations. The
// column definitions mirror the .table specs so that the virtual table layer
// maps used columns and constraints exactly as it does in osqueryi.
class ProcessesTestPlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("pid", BIGINT_TYPE, ColumnOptions::INDEX),
        std::make_tuple("name", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("path", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("cmdline", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("state", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("cwd", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("root", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("uid", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("gid", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("euid", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("egid", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("suid", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("sgid", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("on_disk", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("wired_size", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("resident_size", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("total_size", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("user_time", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("system_time", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("disk_bytes_read", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("disk_bytes_written",
                        BIGINT_TYPE,
                        ColumnOptions::DEFAULT),
        std::make_tuple("start_time", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("parent", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("pgroup", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("threads", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("nice", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("cgroup_path", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("label", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

  TableRows generate(QueryContext& context) override {
    return tables::genProcesses(context);
  }
};

class FileTestPlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("path",
                        TEXT_TYPE,
                        ColumnOptions::INDEX | ColumnOptions::REQUIRED |
                            ColumnOptions::OPTIMIZED),
        std::make_tuple("directory",
                        TEXT_TYPE,
                        ColumnOptions::REQUIRED | ColumnOptions::OPTIMIZED),
        std::make_tuple("filename", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("inode", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("uid", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("gid", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("mode", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("device", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("size", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("block_size", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("atime", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("mtime", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("ctime", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("btime", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("hard_links", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("symlink", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("type", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("symlink_target_path",
                        TEXT_TYPE,
                        ColumnOptions::DEFAULT),
        std::make_tuple("pid_with_namespace",
                        INTEGER_TYPE,
                        ColumnOptions::HIDDEN),
    };
  }

  TableRows generate(QueryContext& context) override {
    return tableRowsFromQueryData(tables::genFile(context));
  }
};

class SocketsTestPlugin : public TablePlugin {
 private:
  TableColumns columns() const override {
    return {
        std::make_tuple("pid", INTEGER_TYPE, ColumnOptions::ADDITIONAL),
        std::make_tuple("fd", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("socket", BIGINT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("family", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("protocol", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("local_address", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("remote_address", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("local_port", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("remote_port", INTEGER_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("path", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("state", TEXT_TYPE, ColumnOptions::DEFAULT),
        std::make_tuple("net_namespace", TEXT_TYPE, ColumnOptions::DEFAULT),
    };
  }

  TableRows generate(QueryContext& context) override {
    return tableRowsFromQueryData(tables::genOpenSockets(context));
  }
};

// Sort rows so that two result sets can be compared row by row.
QueryData sorted(QueryData rows) {
  std::sort(rows.begin(), rows.end());
  return rows;
}

} // namespace

class ColumnPruningEndToEndTest : public testing::Test {
 public:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();

    auto tables = RegistryFactory::get().registry("table");
    for (const auto& name : {"processes", "file", "process_open_sockets"}) {
      if (tables->exists(name)) {
        tables->remove(name);
      }
    }
    tables->add("processes", std::make_shared<ProcessesTestPlugin>());
    tables->add("file", std::make_shared<FileTestPlugin>());
    tables->add("process_open_sockets", std::make_shared<SocketsTestPlugin>());

    // getUnique() attaches every registered table to the new connection.
    dbc_ = SQLiteDBManager::getUnique();
  }

  void TearDown() override {
    FLAGS_enable_column_pruning = true;
  }

  QueryData run(const std::string& query) {
    QueryData results;
    auto status = queryInternal(query, results, dbc_);
    EXPECT_TRUE(status.ok()) << query << ": " << status.getMessage();
    return results;
  }

  // Run the same query with pruning off and on; the results must be
  // identical, row by row and field by field.
  void expectSameResults(const std::string& query) {
    FLAGS_enable_column_pruning = false;
    auto unpruned = sorted(run(query));
    dbc_->clearAffectedTables();

    FLAGS_enable_column_pruning = true;
    auto pruned = sorted(run(query));
    dbc_->clearAffectedTables();

    EXPECT_EQ(pruned, unpruned) << "results diverge for: " << query;
  }

  SQLiteDBInstanceRef dbc_;
};

TEST_F(ColumnPruningEndToEndTest, processes_subset_columns) {
  const auto pid = std::to_string(getpid());
  // Stable columns only: cpu times and memory sizes can change between the
  // two runs of the query.
  expectSameResults(
      "SELECT pid, name, path, cmdline, cwd, root, uid, gid, euid, egid, "
      "suid, sgid, parent, pgroup, state, nice, threads, on_disk, "
      "start_time, cgroup_path, label FROM processes WHERE pid = " +
      pid);
}

TEST_F(ColumnPruningEndToEndTest, processes_all_columns) {
  const auto pid = std::to_string(getpid());
  expectSameResults(
      "SELECT pid, name, path, cmdline, cwd, root, uid, gid, euid, egid, "
      "suid, sgid, parent, pgroup, state, nice, threads, on_disk, "
      "start_time, cgroup_path, label FROM processes WHERE pid = " +
      pid);
}

TEST_F(ColumnPruningEndToEndTest, processes_count_star) {
  const auto pid = std::to_string(getpid());
  // Constrained to stable processes: a full-scan count can change between
  // the pruning-off and pruning-on runs.
  expectSameResults("SELECT count(*) AS n FROM processes WHERE pid = " + pid);
  expectSameResults(
      "SELECT state, count(*) AS n FROM processes WHERE pid IN (" + pid +
      ", 1) GROUP BY state");
}

TEST_F(ColumnPruningEndToEndTest, processes_aggregates) {
  const auto pid = std::to_string(getpid());
  expectSameResults(
      "SELECT min(uid) AS lo, max(uid) AS hi, count(*) AS n FROM processes "
      "WHERE pid IN (" +
      pid + ", 1)");
}

TEST_F(ColumnPruningEndToEndTest, processes_join_with_file) {
  // A join must keep the column requirements of the two tables separate:
  // file needs path/directory for its required constraints, processes only
  // the join and projection columns.
  const auto pid = std::to_string(getpid());
  expectSameResults(
      "SELECT p.pid, p.name, f.path, f.size FROM processes p, file f "
      "WHERE p.pid = " +
      pid + " AND f.path = '/etc/hostname'");
}

TEST_F(ColumnPruningEndToEndTest, processes_subquery_same_table) {
  // The outer query and the subquery scan processes through different
  // cursors; column requirements must be merged for the shared table.
  const auto pid = std::to_string(getpid());
  expectSameResults(
      "SELECT pid, name FROM processes WHERE uid IN (SELECT uid FROM "
      "processes WHERE pid = " +
      pid + ") AND pid IN (" + pid + ", 1) ORDER BY pid");
}

TEST_F(ColumnPruningEndToEndTest, file_table_results) {
  // A deterministic directory with a regular file, a subdirectory and a
  // symlink.
  const auto root = fs::temp_directory_path() / fs::unique_path("pruning%%%%");
  ASSERT_TRUE(fs::create_directories(root / "subdir"));
  {
    std::ofstream file((root / "regular.txt").string());
    file << "data";
  }
  fs::create_symlink(root / "regular.txt", root / "link");

  const auto directory = root.string();
  expectSameResults("SELECT * FROM file WHERE directory = '" + directory +
                    "'");
  expectSameResults(
      "SELECT path, filename, type FROM file WHERE directory = '" + directory +
      "'");
  expectSameResults("SELECT path FROM file WHERE directory = '" + directory +
                    "'");
  expectSameResults("SELECT count(*) AS n FROM file WHERE directory = '" +
                    directory + "'");
  expectSameResults(
      "SELECT path, symlink_target_path FROM file WHERE path = '" +
      (root / "link").string() + "'");

  fs::remove_all(root);
}

TEST_F(ColumnPruningEndToEndTest, process_open_sockets_results) {
  // Open a listening socket so this process owns at least one row.
  const auto fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  struct sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  ASSERT_EQ(bind(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)),
            0);
  ASSERT_EQ(listen(fd, 1), 0);

  const auto pid = std::to_string(getpid());
  expectSameResults(
      "SELECT * FROM process_open_sockets WHERE pid = " + pid);
  expectSameResults(
      "SELECT local_address, local_port, state, protocol FROM "
      "process_open_sockets WHERE pid = " +
      pid);
  expectSameResults(
      "SELECT count(*) AS n FROM process_open_sockets WHERE pid = " + pid);

  close(fd);
}

// Not a correctness test: prints the wall time of the planning phase
// (sqlite3_prepare, which runs xBestIndex) and the data generation phase
// (sqlite3_step, which runs xFilter/generate) with pruning off and on.
TEST_F(ColumnPruningEndToEndTest, plan_and_generate_timing) {
  const std::vector<std::string> queries = {
      "SELECT pid, name, uid FROM processes",
      "SELECT * FROM processes",
      "SELECT count(*) AS n FROM processes",
      "SELECT local_port, state FROM process_open_sockets WHERE pid = -1",
      "SELECT local_port, state FROM process_open_sockets",
      "SELECT * FROM process_open_sockets WHERE pid = -1",
      "SELECT path FROM file WHERE directory = '/usr/bin'",
      "SELECT * FROM file WHERE directory = '/usr/bin'",
  };

  for (const auto pruning : {false, true}) {
    FLAGS_enable_column_pruning = pruning;
    for (const auto& query : queries) {
      double best_plan_ms = 0.0;
      double best_generate_ms = 0.0;
      size_t rows = 0;
      for (size_t i = 0; i < 5; i++) {
        sqlite3_stmt* stmt{nullptr};
        const auto t0 = std::chrono::steady_clock::now();
        auto rc = sqlite3_prepare_v2(dbc_->db(), query.c_str(), -1, &stmt,
                                     nullptr);
        const auto t1 = std::chrono::steady_clock::now();
        ASSERT_EQ(rc, SQLITE_OK) << query;

        rows = 0;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
          rows++;
        }
        const auto t2 = std::chrono::steady_clock::now();
        EXPECT_EQ(rc, SQLITE_DONE) << query;
        sqlite3_finalize(stmt);
        dbc_->clearAffectedTables();

        const auto plan_ms =
            std::chrono::duration<double, std::milli>(t1 - t0).count();
        const auto generate_ms =
            std::chrono::duration<double, std::milli>(t2 - t1).count();
        if (i == 0 || plan_ms < best_plan_ms) {
          best_plan_ms = plan_ms;
        }
        if (i == 0 || generate_ms < best_generate_ms) {
          best_generate_ms = generate_ms;
        }
      }

      printf("[timing] pruning=%-3s rows=%-5zu plan=%8.3fms generate=%8.3fms "
             "| %s\n",
             pruning ? "on" : "off", rows, best_plan_ms, best_generate_ms,
             query.c_str());
    }
  }
}

} // namespace osquery
