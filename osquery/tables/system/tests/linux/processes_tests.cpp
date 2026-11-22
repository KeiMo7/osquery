/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <osquery/core/tables.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/tables/system/linux/processes.h>

#include <unistd.h>

namespace osquery {
namespace tables {

namespace {
// Join entries into a nul-delimited block, the way /proc/<pid>/environ is laid
// out.
std::string environBlock(const std::vector<std::string>& entries) {
  std::string content;
  for (const auto& entry : entries) {
    content += entry;
    content.push_back('\0');
  }
  return content;
}
} // namespace

class CGroupTest : public ::testing::Test {};

TEST_F(CGroupTest, systemd_session) {
  auto got =
      parseProcCGroup("0::/user.slice/user-1000.slice/session-6.scope\n");
  EXPECT_EQ("/user.slice/user-1000.slice/session-6.scope", got);
}

TEST_F(CGroupTest, no_newline) {
  auto got = parseProcCGroup("0::/user.slice/user-1000.slice/session-6.scope");
  EXPECT_EQ("/user.slice/user-1000.slice/session-6.scope", got);
}

TEST_F(CGroupTest, version_1_single_group) {
  auto got = parseProcCGroup(
      "4:cpu,cpuset:/user.slice/user-1000.slice/session-6.scope\n");
  EXPECT_EQ("/user.slice/user-1000.slice/session-6.scope", got);
}

TEST_F(CGroupTest, invalid) {
  auto got = parseProcCGroup("0:/user.slice\n");
  EXPECT_EQ("", got);
}

class ProcMapsInodeTest : public ::testing::Test {};

TEST_F(ProcMapsInodeTest, binary_path) {
  auto got = parseProcMapsInode(
      "55d0c0a00000-55d0c0a02000 r--p 00000000 08:01 1312 /usr/bin/cat\n"
      "55d0c0a02000-55d0c0a07000 r-xp 00002000 08:01 1312 /usr/bin/cat\n",
      "/usr/bin/cat");
  EXPECT_EQ("1312", got);
}

TEST_F(ProcMapsInodeTest, path_with_regex_characters) {
  const std::string path = "/tmp/a+[b]\\h (deleted)";
  auto got = parseProcMapsInode(
      "7f0000000000-7f0000001000 r--p 00000000 08:01 42 /usr/lib/libc.so.6\n"
      "55d0c0a00000-55d0c0a02000 r-xp 00000000 08:01 1312                  " +
          path + "\n",
      path);
  EXPECT_EQ("1312", got);
}

TEST_F(ProcMapsInodeTest, path_with_newline) {
  auto got = parseProcMapsInode(
      "55d0c0a00000-55d0c0a02000 r-xp 00000000 08:01 1312 "
      "/tmp/a\\012b (deleted)\n",
      "/tmp/a\nb (deleted)");
  EXPECT_EQ("1312", got);
}

TEST_F(ProcMapsInodeTest, path_not_mapped) {
  auto got = parseProcMapsInode(
      "55d0c0a00000-55d0c0a02000 r-xp 00000000 08:01 1312 /tmp/a (deleted)x\n"
      "7ffc0a000000-7ffc0a021000 rw-p 00000000 00:00 0 [stack]\n",
      "/tmp/a (deleted)");
  EXPECT_EQ("", got);
}

class ProcEnvironTest : public ::testing::Test {};

TEST_F(ProcEnvironTest, well_formed) {
  auto got =
      parseProcessEnvironment(environBlock({"PATH=/usr/bin", "HOME=/root"}));
  ASSERT_EQ(2u, got.size());
  EXPECT_EQ("PATH", got[0].first);
  EXPECT_EQ("/usr/bin", got[0].second);
  EXPECT_EQ("HOME", got[1].first);
  EXPECT_EQ("/root", got[1].second);
}

TEST_F(ProcEnvironTest, high_bit_name_does_not_truncate) {
  // An entry whose name begins with a byte that has the high bit set is a
  // negative value where char is signed. The walk must not stop there and
  // drop the entries that follow it.
  auto content = environBlock({"PATH=/usr/bin",
                               std::string(1, static_cast<char>(0xA3)) + "M=x",
                               "LD_PRELOAD=/tmp/x.so"});
  auto got = parseProcessEnvironment(content);
  ASSERT_EQ(3u, got.size());
  EXPECT_EQ("LD_PRELOAD", got[2].first);
  EXPECT_EQ("/tmp/x.so", got[2].second);
}

TEST_F(ProcEnvironTest, no_trailing_nul) {
  // A block with no nul anywhere, as seen from a process that overwrote its
  // own environ region, must be read within bounds and still yield its entry.
  auto got = parseProcessEnvironment(std::string(64, 'A'));
  ASSERT_EQ(1u, got.size());
  EXPECT_EQ(std::string(64, 'A'), got[0].first);
}

// Defined in linux/processes.cpp.
TableRows genProcesses(QueryContext& context);

class ProcessesColumnPruningTest : public ::testing::Test {
 protected:
  static std::string selfPid() {
    return std::to_string(getpid());
  }

  // A context constrained to this process, with the given used columns.
  static QueryContext prunedContext(
      std::initializer_list<std::string> columns) {
    QueryContext context;
    context.constraints["pid"].add(Constraint(EQUALS, selfPid()));
    context.colsUsed = UsedColumns(columns);
    return context;
  }

  // A context constrained to this process, computing every column.
  static QueryContext unprunedContext() {
    QueryContext context;
    context.constraints["pid"].add(Constraint(EQUALS, selfPid()));
    return context;
  }

  static Row generateOne(QueryContext context) {
    auto rows = genProcesses(context);
    EXPECT_EQ(rows.size(), 1U);
    return rows.empty() ? Row() : static_cast<Row>(*rows[0]);
  }
};

TEST_F(ProcessesColumnPruningTest, unrequested_columns_are_not_computed) {
  auto row = generateOne(prunedContext({"pid", "name"}));

  EXPECT_EQ(row.at("pid"), selfPid());
  EXPECT_FALSE(row.at("name").empty());

  // Columns that each require reading extra /proc entries must be absent.
  for (const auto& column :
       {"cmdline", "path", "on_disk", "cwd", "root", "label", "cgroup_path",
        "disk_bytes_read", "disk_bytes_written"}) {
    EXPECT_EQ(row.count(column), 0U) << "column " << column << " was computed";
  }
}

TEST_F(ProcessesColumnPruningTest, unpruned_context_computes_everything) {
  auto row = generateOne(unprunedContext());

  for (const auto& column :
       {"cmdline", "path", "on_disk", "cwd", "root", "label",
        "disk_bytes_read", "disk_bytes_written"}) {
    EXPECT_EQ(row.count(column), 1U) << "column " << column << " is missing";
  }
}

TEST_F(ProcessesColumnPruningTest, pruned_values_match_unpruned) {
  const std::initializer_list<std::string> requested = {
      "pid",   "name",  "path",   "cmdline", "cwd",   "root", "uid",
      "gid",   "euid",  "egid",   "parent",  "state", "nice", "threads",
      "on_disk", "start_time", "label"};

  auto pruned = generateOne(prunedContext(requested));
  auto unpruned = generateOne(unprunedContext());

  for (const auto& column : requested) {
    ASSERT_EQ(pruned.count(column), 1U) << column;
    ASSERT_EQ(unpruned.count(column), 1U) << column;
    EXPECT_EQ(pruned.at(column), unpruned.at(column)) << "column " << column;
  }
}

TEST_F(ProcessesColumnPruningTest, empty_column_set_keeps_row_count) {
  // count(*) semantics: no column is used, but the row must still exist.
  auto pruned = prunedContext({});
  auto rows = genProcesses(pruned);
  EXPECT_EQ(rows.size(), 1U);

  auto unpruned = unprunedContext();
  auto unpruned_rows = genProcesses(unpruned);
  EXPECT_EQ(rows.size(), unpruned_rows.size());
}

TEST_F(ProcessesColumnPruningTest, path_on_disk_dependency_group) {
  auto unpruned = generateOne(unprunedContext());

  // Requesting only path must still run the on_disk computation, which can
  // strip a " (deleted)" suffix from path.
  auto path_only = generateOne(prunedContext({"path"}));
  EXPECT_EQ(path_only.count("on_disk"), 0U);
  EXPECT_EQ(path_only.at("path"), unpruned.at("path"));

  // Requesting only on_disk must compute (but not emit) path.
  auto on_disk_only = generateOne(prunedContext({"on_disk"}));
  EXPECT_EQ(on_disk_only.count("path"), 0U);
  EXPECT_EQ(on_disk_only.at("on_disk"), unpruned.at("on_disk"));
}

TEST_F(ProcessesColumnPruningTest, column_error_identifies_column) {
  try {
    computeColumnValue("cmdline", []() -> std::string {
      throw std::runtime_error("boom");
    });
    FAIL() << "expected an exception";
  } catch (const std::exception& e) {
    EXPECT_NE(std::string(e.what()).find("cmdline"), std::string::npos)
        << e.what();
    EXPECT_NE(std::string(e.what()).find("boom"), std::string::npos)
        << e.what();
  }
}

} // namespace tables
} // namespace osquery
