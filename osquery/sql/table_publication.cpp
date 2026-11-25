/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/sql/table_publication.h>

#include <algorithm>
#include <cctype>
#include <condition_variable>
#include <mutex>
#include <set>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <osquery/core/flags.h>
#include <osquery/core/shutdown.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/virtual_table.h>

namespace osquery {

FLAG(int32,
     table_publication_drain_timeout_ms,
     500,
     "Default maximum time to wait for table cursors to drain");

namespace {

struct PublicationState {
  std::mutex publish_mutex;
  ConstTableSnapshotPtr current;

  std::mutex cursor_mutex;
  std::condition_variable cursor_cv;
  std::unordered_map<std::string, std::size_t> cursors;
  std::size_t total_cursors{0};
  std::set<std::string> pending_retirements;

  PublicationState() {
    auto initial = std::make_shared<TableSnapshot>();
    initial->generation = 0;
    initial->content_hash = "";
    current = std::static_pointer_cast<const TableSnapshot>(initial);
  }
};

PublicationState& state() {
  static PublicationState instance;
  return instance;
}

// Shared objects placed here are moved to a detached releaser when a publish
// call leaves scope. This prevents the final plugin/snapshot reference from
// being destroyed while publish_mutex_ (or an outer config lock) is held.
struct AsyncReferenceReleaser {
  std::vector<std::shared_ptr<const void>> references;

  AsyncReferenceReleaser() = default;
  AsyncReferenceReleaser(const AsyncReferenceReleaser&) = delete;
  AsyncReferenceReleaser& operator=(const AsyncReferenceReleaser&) = delete;

  ~AsyncReferenceReleaser() {
    if (references.empty()) {
      return;
    }

    std::thread([held = std::move(references)]() mutable {
      // The references are intentionally destroyed in this worker's
      // stack, outside every publication/config critical section.
      (void)held;
    }).detach();
  }
};

bool isAbsoluteFileSystemPath(const std::string& path) {
  if (!path.empty() && path.front() == '/') {
    return true;
  }

  // Windows-style absolute paths are accepted even when validation runs on a
  // POSIX host, because the same configuration may be published on Windows.
  if (path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) &&
      path[1] == ':' && (path[2] == '\\' || path[2] == '/')) {
    return true;
  }

  if (path.size() >= 2 && path[0] == '\\' &&
      (path[1] == '\\' || path[1] == '/')) {
    return true;
  }

  return false;
}

std::string lowerAscii(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](char c) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  });
  return value;
}

bool isSqlTokenChar(char c) {
  return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
}

std::vector<std::string> sqlTokens(const std::string& sql) {
  std::vector<std::string> tokens;
  for (std::size_t i = 0; i < sql.size();) {
    if (!isSqlTokenChar(sql[i])) {
      ++i;
      continue;
    }

    std::size_t begin = i;
    while (i < sql.size() && isSqlTokenChar(sql[i])) {
      ++i;
    }
    tokens.push_back(lowerAscii(sql.substr(begin, i - begin)));
  }
  return tokens;
}

Status invalid(std::string& reason, const std::string& message) {
  reason = message;
  return Status(1, message);
}

struct RegistryMutation {
  std::string name;
  bool added_new{false};
  bool existed{false};
  PluginRef old_plugin;
};

} // namespace

TablePublicationRegistry& TablePublicationRegistry::get() {
  static TablePublicationRegistry registry;
  return registry;
}

TablePublicationRegistry& TablePublicationRegistry::instance() {
  return get();
}

TablePublicationRegistry& TablePublicationRegistry::getInstance() {
  return get();
}

TablePublicationRegistry& TablePublicationRegistry::Instance() {
  return get();
}

TablePublicationRegistry& TablePublicationRegistry::Get() {
  return get();
}

TablePublicationRegistry::Duration
TablePublicationRegistry::defaultDrainTimeout() {
  auto milliseconds = FLAGS_table_publication_drain_timeout_ms;
  if (milliseconds <= 0) {
    return Duration(500);
  }
  return Duration(milliseconds);
}

ConstTableSnapshotPtr TablePublicationRegistry::snapshot() {
  auto& publication_state = state();
  return std::atomic_load_explicit(&publication_state.current,
                                   std::memory_order_acquire);
}

Status TablePublicationRegistry::validate(const TableEntryPtr& entry,
                                          std::string& reason) {
  if (!entry) {
    return invalid(reason, "table entry is null");
  }
  return validate(*entry, reason);
}

Status TablePublicationRegistry::validate(const ConstTableEntryPtr& entry,
                                          std::string& reason) {
  if (!entry) {
    return invalid(reason, "table entry is null");
  }
  return validate(*entry, reason);
}

Status TablePublicationRegistry::validate(const TableEntry& entry,
                                          std::string& reason) {
  static const std::unordered_set<std::string> kWriteKeywords = {
      "insert",
      "update",
      "delete",
      "replace",
      "create",
      "drop",
      "alter",
      "truncate",
      "vacuum",
      "reindex",
  };

  const auto& name = entry.name;
  if (name.empty()) {
    return invalid(reason, "table name must not be empty");
  }

  if (name.size() > 64) {
    return invalid(
        reason, "table name '" + name + "' is too long: maximum 64 characters");
  }

  if (name.empty() || !std::islower(static_cast<unsigned char>(name.front())) ||
      !std::isalpha(static_cast<unsigned char>(name.front()))) {
    return invalid(
        reason,
        "table name '" + name + "' must start with a lowercase ASCII letter");
  }

  for (std::size_t i = 1; i < name.size(); ++i) {
    char c = name[i];
    bool valid = std::islower(static_cast<unsigned char>(c)) ||
                 std::isdigit(static_cast<unsigned char>(c)) || c == '_';
    if (!valid) {
      return invalid(
          reason,
          "table name '" + name + "' must match ^[a-z][a-z0-9_]{0,63}$");
    }
  }

  if (entry.columns.size() > 64) {
    return invalid(
        reason, "table '" + name + "' has more than the maximum of 64 columns");
  }

  std::unordered_set<std::string> column_names;
  column_names.reserve(entry.columns.size());
  for (const auto& column : entry.columns) {
    const auto& column_name = std::get<0>(column);
    if (column_name.empty()) {
      return invalid(reason, "table '" + name + "' contains an empty column");
    }

    auto folded = lowerAscii(column_name);
    if (!column_names.insert(folded).second) {
      return invalid(reason,
                     "table '" + name + "' contains duplicate column '" +
                         column_name + "'");
    }
  }

  const auto& sql = entry.sql.empty() ? entry.query : entry.sql;
  if (sql.empty()) {
    if (entry.requires_sqlite_source) {
      return invalid(reason, "table '" + name + "' is missing its SQL query");
    }
  } else {
    if (sql.find(';') != std::string::npos) {
      return invalid(reason,
                     "table '" + name +
                         "' SQL must be one SELECT/WITH statement; semicolon "
                         "is not allowed");
    }

    if (sql.find("--") != std::string::npos ||
        sql.find("/*") != std::string::npos ||
        sql.find("*/") != std::string::npos) {
      return invalid(reason,
                     "table '" + name + "' SQL must not contain comments");
    }

    auto tokens = sqlTokens(sql);
    if (tokens.empty() ||
        (tokens.front() != "select" && tokens.front() != "with")) {
      return invalid(
          reason,
          "table '" + name +
              "' SQL must be a single SELECT or WITH ... SELECT statement");
    }

    for (const auto& token : tokens) {
      if (token == "attach") {
        return invalid(reason,
                       "table '" + name + "' SQL must not contain ATTACH");
      }
      if (token == "pragma") {
        return invalid(reason,
                       "table '" + name + "' SQL must not contain PRAGMA");
      }
      if (kWriteKeywords.count(token) != 0) {
        return invalid(reason,
                       "table '" + name +
                           "' SQL must not contain write statement keyword '" +
                           token + "'");
      }
    }
  }

  if (entry.path.empty()) {
    if (entry.requires_sqlite_source) {
      return invalid(reason, "table '" + name + "' is missing its path");
    }
  } else {
    if (entry.path.find("..") != std::string::npos) {
      return invalid(
          reason,
          "table '" + name +
              "' path must not contain parent-directory segment '..'");
    }

    if (!isAbsoluteFileSystemPath(entry.path)) {
      return invalid(
          reason, "table '" + name + "' path must be absolute: " + entry.path);
    }
  }

  reason.clear();
  return Status::success();
}

Status TablePublicationRegistry::publishEntries(
    std::vector<TableEntryPtr> desired,
    std::vector<std::string> explicit_removals,
    const std::string& content_hash,
    TablePublicationStats* stats_pointer) {
  TablePublicationStats local_stats;
  auto& stats = stats_pointer != nullptr ? *stats_pointer : local_stats;
  stats = TablePublicationStats{};

  auto& publication_state = state();
  AsyncReferenceReleaser async_releaser;
  std::lock_guard<std::mutex> publish_lock(publication_state.publish_mutex);

  if (shutdownRequested()) {
    return Status(1, "shutting down");
  }

  auto current = std::atomic_load_explicit(&publication_state.current,
                                           std::memory_order_acquire);
  async_releaser.references.push_back(current);
  stats.generation = current->generation;
  stats.content_hash = current->content_hash;

  if (content_hash == current->content_hash) {
    return Status(2, "table publication content unchanged");
  }

  std::vector<TableEntryPtr> accepted;
  accepted.reserve(desired.size());

  std::set<std::string> desired_names;
  std::set<std::string> batch_names;
  std::set<std::string> touched_sources;

  for (auto& entry : desired) {
    ++stats.attempted;

    if (!entry) {
      ++stats.failed;
      stats.failed_tables.emplace_back("<null>");
      stats.failed_names.emplace_back("<null>");
      stats.failure_reasons["<null>"] = "table entry is null";
      continue;
    }

    const auto& name = entry->name;
    desired_names.insert(name);

    std::string reason;
    auto validation = validate(*entry, reason);
    if (!validation.ok()) {
      ++stats.skipped;
      stats.skipped_tables.push_back(name);
      stats.skip_reasons[name] = reason;
      continue;
    }

    if (!batch_names.insert(name).second) {
      ++stats.skipped;
      stats.skipped_tables.push_back(name);
      stats.skip_reasons[name] =
          "duplicate table name in publication batch: " + name;
      continue;
    }

    accepted.push_back(entry);
  }

  std::set<std::string> removal_set(explicit_removals.begin(),
                                    explicit_removals.end());

  // An empty desired set is a full generation replacement for callers that do
  // not provide explicit source-scoped removals.
  if (desired.empty() && explicit_removals.empty()) {
    for (const auto& item : current->tables) {
      removal_set.insert(item.first);
    }
  }

  auto next_tables = current->tables;
  for (const auto& name : desired_names) {
    removal_set.erase(name);
  }
  for (const auto& name : removal_set) {
    next_tables.erase(name);
  }

  RegistryInterfaceRef table_registry;
  bool registry_available = false;
  try {
    if (RegistryFactory::get().exists("table")) {
      table_registry = RegistryFactory::get().registry("table");
      registry_available = table_registry != nullptr;
    }
  } catch (const std::exception& e) {
    VLOG(1) << "Table publication registry unavailable: " << e.what();
  }

  std::vector<RegistryMutation> mutations;
  mutations.reserve(accepted.size() + removal_set.size());

  auto rollback_registry = [&]() {
    if (!registry_available) {
      return;
    }
    for (auto it = mutations.rbegin(); it != mutations.rend(); ++it) {
      try {
        if (it->added_new) {
          table_registry->remove(it->name);
        }
        if (it->existed && it->old_plugin) {
          table_registry->add(it->name, it->old_plugin, true);
        }
      } catch (const std::exception& e) {
        VLOG(1) << "Failed to roll back table registry publication for "
                << it->name << ": " << e.what();
      }
    }
  };

  // Remove explicitly/source-deleted publication-owned registry entries.
  for (const auto& name : removal_set) {
    auto old_entry = current->find(name);
    if (!registry_available || !table_registry->exists(name, true)) {
      continue;
    }

    PluginRef existing_plugin;
    try {
      existing_plugin = table_registry->plugin(name);
    } catch (...) {
      existing_plugin = nullptr;
    }

    if (old_entry && old_entry->plugin &&
        existing_plugin ==
            std::static_pointer_cast<Plugin>(old_entry->plugin)) {
      RegistryMutation mutation;
      mutation.name = name;
      mutation.existed = true;
      mutation.old_plugin = existing_plugin;
      mutations.push_back(mutation);
      table_registry->remove(name);
    }
  }

  // Write all accepted plugins to RegistryInterface before the atomic snapshot
  // swap. Individual registry add failures affect only that entry.
  std::vector<TableEntryPtr> attached_candidates;
  for (auto& entry : accepted) {
    const auto& name = entry->name;

    if (!entry->plugin) {
      ++stats.failed;
      stats.failed_tables.push_back(name);
      stats.failed_names.push_back(name);
      stats.failure_reasons[name] = "table entry has no plugin instance";
      continue;
    }

    bool exists_in_registry = false;
    PluginRef existing_plugin;
    if (registry_available) {
      try {
        exists_in_registry = table_registry->exists(name, true);
        if (exists_in_registry) {
          existing_plugin = table_registry->plugin(name);
        }
      } catch (const std::exception& e) {
        ++stats.failed;
        stats.failed_tables.push_back(name);
        stats.failed_names.push_back(name);
        stats.failure_reasons[name] = e.what();
        continue;
      }
    }

    auto old_entry = current->find(name);
    if (exists_in_registry && existing_plugin &&
        existing_plugin != std::static_pointer_cast<Plugin>(entry->plugin)) {
      bool old_owns_plugin =
          old_entry && old_entry->plugin &&
          existing_plugin ==
              std::static_pointer_cast<Plugin>(old_entry->plugin);
      if (!old_owns_plugin) {
        ++stats.skipped;
        stats.skipped_tables.push_back(name);
        stats.skip_reasons[name] =
            "table name conflicts with an existing built-in or extension table";
        continue;
      }
    }

    RegistryMutation mutation;
    mutation.name = name;
    mutation.existed = exists_in_registry;
    mutation.old_plugin = existing_plugin;

    if (registry_available) {
      if (exists_in_registry) {
        table_registry->remove(name);
      }

      auto add_status = table_registry->add(name, entry->plugin, true);
      if (!add_status.ok()) {
        ++stats.failed;
        stats.failed_tables.push_back(name);
        stats.failed_names.push_back(name);
        stats.failure_reasons[name] = add_status.getMessage();

        if (exists_in_registry && existing_plugin) {
          table_registry->add(name, existing_plugin, true);
        }
        continue;
      }
      mutation.added_new = true;
    }

    mutations.push_back(mutation);
    attached_candidates.push_back(entry);
    if (!entry->source.empty()) {
      touched_sources.insert(entry->source);
    }
  }

  // Only successfully accepted sources prune their omitted names. A batch
  // whose entries all failed validation/conflict must not retire old tables.
  for (const auto& item : current->tables) {
    const auto& old_entry = item.second;
    const auto& name = item.first;
    if (!old_entry || desired_names.count(name) != 0 ||
        old_entry->source.empty() ||
        touched_sources.count(old_entry->source) == 0 ||
        removal_set.count(name) != 0) {
      continue;
    }

    removal_set.insert(name);
    next_tables.erase(name);

    if (!registry_available || !table_registry->exists(name, true)) {
      continue;
    }

    PluginRef existing_plugin;
    try {
      existing_plugin = table_registry->plugin(name);
    } catch (...) {
      existing_plugin = nullptr;
    }

    if (old_entry->plugin && existing_plugin &&
        existing_plugin ==
            std::static_pointer_cast<Plugin>(old_entry->plugin)) {
      RegistryMutation mutation;
      mutation.name = name;
      mutation.existed = true;
      mutation.old_plugin = existing_plugin;
      mutations.push_back(mutation);
      table_registry->remove(name);
    }
  }

  // Prove every registry write can create its SQLite virtual table before the
  // new generation becomes observable. An attach failure is transactional.
  for (const auto& mutation : mutations) {
    if (mutation.old_plugin) {
      async_releaser.references.push_back(mutation.old_plugin);
    }
  }

  for (const auto& entry : attached_candidates) {
    auto attach_status = verifyTableEntryForPublication(entry);
    if (!attach_status.ok()) {
      rollback_registry();

      ++stats.failed;
      ++stats.skipped;
      if (std::find(stats.failed_tables.begin(),
                    stats.failed_tables.end(),
                    entry->name) == stats.failed_tables.end()) {
        stats.failed_tables.push_back(entry->name);
        stats.failed_names.push_back(entry->name);
      }
      stats.failure_reasons[entry->name] = attach_status.getMessage();
      stats.skip_reasons[entry->name] = attach_status.getMessage();

      auto code = attach_status.getCode();
      return Status(1,
                    "table publication attach failed for '" + entry->name +
                        "': SQLite error code " + std::to_string(code) + ": " +
                        attach_status.getMessage());
    }
  }

  for (auto& entry : attached_candidates) {
    try {
      if (entry->after_attach_verification) {
        entry->after_attach_verification();
      }
      if (entry->plugin) {
        entry->attributes = entry->plugin->attributes();
      }
    } catch (const std::exception& e) {
      rollback_registry();
      return Status(1,
                    std::string("table publication activation failed for '") +
                        entry->name + "': " + e.what());
    } catch (...) {
      rollback_registry();
      return Status(1,
                    "table publication activation failed for '" + entry->name +
                        "': unknown exception");
    }
  }

  if (attached_candidates.empty() && removal_set.empty()) {
    // Validation/conflict rejections do not mutate the generation. Registry
    // add failures already restored their individual old plugin.
    stats.removed_tables.clear();
    stats.removed_names.clear();
    return Status(1, "table publication contains no usable entries");
  }

  auto next_generation = current->generation + 1;
  auto next_snapshot = std::make_shared<TableSnapshot>();
  next_snapshot->generation = next_generation;
  next_snapshot->content_hash = content_hash;

  for (auto& entry : attached_candidates) {
    entry->generation = next_generation;
    next_tables[entry->name] =
        std::static_pointer_cast<const TableEntry>(entry);

    ++stats.published;
    stats.published_tables.push_back(entry->name);
  }

  for (const auto& name : removal_set) {
    next_tables.erase(name);
  }

  next_snapshot->tables = std::move(next_tables);

  std::atomic_store_explicit(
      &publication_state.current,
      std::static_pointer_cast<const TableSnapshot>(next_snapshot),
      std::memory_order_release);

  stats.generation = next_generation;
  stats.published = stats.published_tables.size();
  stats.removed_tables.assign(removal_set.begin(), removal_set.end());
  stats.removed_names = stats.removed_tables;
  stats.validated = stats.published + stats.skipped;

  // Timeouts from an earlier generation get a non-blocking retry with the
  // publication now complete. Names with live cursors remain pending.
  std::vector<std::string> retry_names;
  {
    std::lock_guard<std::mutex> cursor_lock(publication_state.cursor_mutex);
    retry_names.assign(publication_state.pending_retirements.begin(),
                       publication_state.pending_retirements.end());
  }
  for (const auto& name : retry_names) {
    retire(name, Duration(0));
  }

  return Status::success();
}

Status TablePublicationRegistry::retire(const std::string& name,
                                        Duration timeout) {
  auto& publication_state = state();
  std::unique_lock<std::mutex> lock(publication_state.cursor_mutex);

  auto deadline = std::chrono::steady_clock::now() + timeout;
  bool drained = publication_state.cursor_cv.wait_until(lock, deadline, [&] {
    auto it = publication_state.cursors.find(name);
    return it == publication_state.cursors.end() || it->second == 0;
  });

  if (!drained) {
    publication_state.pending_retirements.insert(name);
    return Status(1, "timed out waiting for table cursors to retire: " + name);
  }

  publication_state.cursors.erase(name);
  publication_state.pending_retirements.erase(name);
  return Status::success();
}

Status TablePublicationRegistry::retire(const std::string& name,
                                        std::uint64_t timeout_ms) {
  return retire(name, Duration(timeout_ms));
}

Status TablePublicationRegistry::drain(Duration timeout) {
  auto& publication_state = state();
  std::unique_lock<std::mutex> lock(publication_state.cursor_mutex);

  auto deadline = std::chrono::steady_clock::now() + timeout;
  bool drained = publication_state.cursor_cv.wait_until(
      lock, deadline, [&] { return publication_state.total_cursors == 0; });

  if (!drained) {
    return Status(1, "timed out waiting for all table cursors to drain");
  }

  return Status::success();
}

Status TablePublicationRegistry::drain(std::uint64_t timeout_ms) {
  return drain(Duration(timeout_ms));
}

void TablePublicationRegistry::acquireCursor(const std::string& name) {
  if (name.empty()) {
    return;
  }

  auto& publication_state = state();
  std::lock_guard<std::mutex> lock(publication_state.cursor_mutex);
  ++publication_state.cursors[name];
  ++publication_state.total_cursors;
}

void TablePublicationRegistry::releaseCursor(const std::string& name) {
  if (name.empty()) {
    return;
  }

  auto& publication_state = state();
  {
    std::lock_guard<std::mutex> lock(publication_state.cursor_mutex);
    auto it = publication_state.cursors.find(name);
    if (it != publication_state.cursors.end() && it->second > 0) {
      --it->second;
      if (it->second == 0) {
        publication_state.cursors.erase(it);
      }
    }
    if (publication_state.total_cursors > 0) {
      --publication_state.total_cursors;
    }
  }
  publication_state.cursor_cv.notify_all();
}

void TablePublicationRegistry::resetForTesting() {
  auto& publication_state = state();
  {
    std::lock_guard<std::mutex> publish_lock(publication_state.publish_mutex);
    auto initial = std::make_shared<TableSnapshot>();
    std::atomic_store_explicit(
        &publication_state.current,
        std::static_pointer_cast<const TableSnapshot>(initial),
        std::memory_order_release);
  }

  {
    std::lock_guard<std::mutex> cursor_lock(publication_state.cursor_mutex);
    publication_state.cursors.clear();
    publication_state.total_cursors = 0;
    publication_state.pending_retirements.clear();
  }
  publication_state.cursor_cv.notify_all();
}

void TablePublicationRegistry::seedSnapshotForTesting(
    ConstTableSnapshotPtr snapshot) {
  auto& publication_state = state();
  std::lock_guard<std::mutex> publish_lock(publication_state.publish_mutex);
  if (!snapshot) {
    snapshot = std::make_shared<const TableSnapshot>();
  }
  std::atomic_store_explicit(
      &publication_state.current, snapshot, std::memory_order_release);
}

std::vector<std::string>
TablePublicationRegistry::pendingRetirementsForTesting() {
  auto& publication_state = state();
  std::lock_guard<std::mutex> lock(publication_state.cursor_mutex);
  return {publication_state.pending_retirements.begin(),
          publication_state.pending_retirements.end()};
}

} // namespace osquery
