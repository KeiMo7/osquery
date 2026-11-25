/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include <osquery/core/tables.h>
#include <osquery/utils/status/status.h>

namespace osquery {

using TableEntryPtr = std::shared_ptr<TableEntry>;
using ConstTableEntryPtr = std::shared_ptr<const TableEntry>;
using TableSnapshotMap = std::map<std::string, ConstTableEntryPtr>;

/**
 * @brief Map that also supports the snapshot.tables() accessor spelling.
 */
struct CallableTableMap : TableSnapshotMap {
  using TableSnapshotMap::TableSnapshotMap;
  using TableSnapshotMap::operator=;

  const CallableTableMap& operator()() const {
    return *this;
  }

  CallableTableMap& operator()() {
    return *this;
  }
};

/**
 * @brief An immutable generation of published tables.
 *
 * Snapshots are exchanged as one std::shared_ptr via a single atomic shared
 * pointer store. Readers may hold the snapshot or an individual entry for as
 * long as they are executing without taking a publication lock.
 */
struct TableSnapshot {
  uint64_t generation{0};
  std::string content_hash;
  CallableTableMap tables;

  /// Return a table from this generation, or nullptr when it is absent.
  ConstTableEntryPtr find(const std::string& name) const {
    auto it = tables.find(name);
    return it == tables.end() ? nullptr : it->second;
  }

  /// Read-only access to the complete generation map.
  const TableSnapshotMap& all() const {
    return tables;
  }
};

using TableSnapshotPtr = std::shared_ptr<TableSnapshot>;
using ConstTableSnapshotPtr = std::shared_ptr<const TableSnapshot>;

/**
 * @brief Result counters and per-table diagnostics for one publication.
 */
struct TablePublicationStats {
  uint64_t generation{0};
  std::string content_hash;

  size_t attempted{0};
  size_t validated{0};
  size_t published{0};
  size_t skipped{0};
  size_t failed{0};
  size_t retired{0};

  std::vector<std::string> published_tables;
  std::vector<std::string> skipped_tables;
  std::vector<std::string> failed_tables;
  std::vector<std::string> removed_tables;
  std::vector<std::string> retired_tables;

  /// name -> human-readable validation or publication reason.
  std::map<std::string, std::string> skip_reasons;
  std::map<std::string, std::string> failure_reasons;

  /// Compatibility aliases for tests that expect "names" wording.
  std::vector<std::string> failed_names;
  std::vector<std::string> removed_names;
};

namespace table_publication_detail {

template <typename T, typename = void>
struct IsMapContainer : std::false_type {};

template <typename T>
struct IsMapContainer<
    T,
    std::void_t<typename T::key_type, typename T::mapped_type>>
    : std::true_type {};

inline TableEntryPtr makeEntryPtr(const TableEntry& entry) {
  return std::make_shared<TableEntry>(entry);
}

inline TableEntryPtr makeEntryPtr(const TableEntryPtr& entry) {
  return entry;
}

inline TableEntryPtr makeEntryPtr(const ConstTableEntryPtr& entry) {
  // Publication inputs are expected to be mutable before publication; an
  // already-const entry can still be republished through a copied object.
  return entry ? std::make_shared<TableEntry>(*entry) : nullptr;
}

template <typename Container>
std::vector<TableEntryPtr> normalizeDesired(const Container& desired) {
  std::vector<TableEntryPtr> entries;

  if constexpr (IsMapContainer<Container>::value) {
    entries.reserve(desired.size());
    for (const auto& item : desired) {
      if constexpr (std::is_same_v<typename Container::mapped_type,
                                   TableEntry>) {
        entries.push_back(makeEntryPtr(item.second));
      } else {
        entries.push_back(makeEntryPtr(item.second));
      }
    }
  } else {
    entries.reserve(desired.size());
    for (const auto& item : desired) {
      entries.push_back(makeEntryPtr(item));
    }
  }

  return entries;
}

} // namespace table_publication_detail

/**
 * @brief Process-wide atomic table publication and cursor retirement state.
 *
 * The public mutation methods are static so both
 * TablePublicationRegistry::publish(...) and registry.publish(...) call forms
 * refer to the same virtual-table state. Instances are still constructible for
 * callers that prefer ordinary object syntax.
 */
class TablePublicationRegistry {
 public:
  using Duration = std::chrono::milliseconds;

  TablePublicationRegistry() = default;

  /// Allow both registry.get().method() and registry.get()->method() styles.
  TablePublicationRegistry* operator->() {
    return this;
  }

  const TablePublicationRegistry* operator->() const {
    return this;
  }

  /// Process singleton. The API is static; this is provided for object-style
  /// call sites and compatibility with singleton-oriented tests.
  static TablePublicationRegistry& get();
  static TablePublicationRegistry& instance();
  static TablePublicationRegistry& getInstance();
  static TablePublicationRegistry& Instance();
  static TablePublicationRegistry& Get();

  /// Default bounded drain wait, adjustable with a command-line flag.
  static Duration defaultDrainTimeout();

  /// Lock-free-ish snapshot read. Never acquires publish_mutex_.
  static ConstTableSnapshotPtr snapshot();

  /// Validate name, columns, SQL, and path without opening a database.
  static Status validate(const TableEntry& entry, std::string& reason);
  static Status validate(const TableEntryPtr& entry, std::string& reason);
  static Status validate(const ConstTableEntryPtr& entry, std::string& reason);

  /// Canonical implementation. Explicit removals are published atomically
  /// with desired entries.
  static Status publishEntries(std::vector<TableEntryPtr> desired,
                               std::vector<std::string> explicit_removals,
                               const std::string& content_hash,
                               TablePublicationStats* stats);

  template <typename Desired>
  static Status publish(const Desired& desired,
                        const std::string& content_hash,
                        TablePublicationStats& stats) {
    auto entries = table_publication_detail::normalizeDesired(desired);
    return publishEntries(std::move(entries), {}, content_hash, &stats);
  }

  template <typename Desired>
  static Status publish(const Desired& desired,
                        std::vector<std::string> explicit_removals,
                        const std::string& content_hash,
                        TablePublicationStats& stats) {
    auto entries = table_publication_detail::normalizeDesired(desired);
    return publishEntries(
        std::move(entries), std::move(explicit_removals), content_hash, &stats);
  }

  template <typename Desired>
  static Status publish(const Desired& desired,
                        const std::string& content_hash) {
    TablePublicationStats stats;
    auto entries = table_publication_detail::normalizeDesired(desired);
    return publishEntries(std::move(entries), {}, content_hash, &stats);
  }

  /// Wait for one table's cursors to drain. On timeout the name is retained in
  /// pending_retire_ and retried by the next publication.
  static Status retire(const std::string& name,
                       Duration timeout = defaultDrainTimeout());
  static Status retire(const std::string& name, std::uint64_t timeout_ms);

  /// Wait for all publication-tracked cursors to close.
  static Status drain(Duration timeout = defaultDrainTimeout());
  static Status drain(std::uint64_t timeout_ms);

  /// Cursor reference counting used by xOpen/xClose.
  static void acquireCursor(const std::string& name);
  static void releaseCursor(const std::string& name);

  /// Test/setup helper to restore generation zero and remove all state.
  static void resetForTesting();

  /// Test/setup helper to install a specifically constructed old generation.
  static void seedSnapshotForTesting(ConstTableSnapshotPtr snapshot);

  /// Names that timed out during retirement.
  static std::vector<std::string> pendingRetirementsForTesting();
};

} // namespace osquery
