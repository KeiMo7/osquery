/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/core/tables.h>
#include <osquery/utils/mutex.h>

namespace osquery {

/**
 * @brief Registry of table-declared column dependency/side effect groups.
 *
 * Table implementations register their ColumnDependencyMap at static
 * initialization time. The virtual table layer consults the registry once per
 * table and caches the result on VirtualTableContent, so the table plugin
 * interface itself is unchanged and generated plugin classes do not need
 * regeneration.
 */
class ColumnDependencyRegistry {
 public:
  static ColumnDependencyRegistry& instance() {
    static ColumnDependencyRegistry registry;
    return registry;
  }

  void add(const std::string& table_name, ColumnDependencyMap dependencies) {
    WriteLock lock(mutex_);
    dependencies_[table_name] = std::move(dependencies);
  }

  ColumnDependencyMap get(const std::string& table_name) const {
    ReadLock lock(mutex_);
    auto it = dependencies_.find(table_name);
    if (it == dependencies_.end()) {
      return {};
    }
    return it->second;
  }

  bool exists(const std::string& table_name) const {
    ReadLock lock(mutex_);
    return dependencies_.find(table_name) != dependencies_.end();
  }

 private:
  ColumnDependencyRegistry() = default;
  mutable Mutex mutex_;
  std::unordered_map<std::string, ColumnDependencyMap> dependencies_;
};

/// Static-initialization helper for table implementation translation units.
struct ColumnDependencyRegistrar {
  ColumnDependencyRegistrar(const std::string& table_name,
                            ColumnDependencyMap dependencies) {
    ColumnDependencyRegistry::instance().add(
        table_name, std::move(dependencies));
  }
};

/**
 * Declare column dependencies for a table without touching its generated
 * plugin class. Place at namespace scope in the table implementation file.
 */
#define OSQUERY_REGISTER_COLUMN_DEPENDENCIES(table_name, ...)                 \
  namespace {                                                                  \
  const ::osquery::ColumnDependencyRegistrar                                  \
      k_column_dependencies_for_##table_name(#table_name,                     \
                                             ::osquery::ColumnDependencyMap{ \
                                                 __VA_ARGS__});               \
  }

} // namespace osquery
