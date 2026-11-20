/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <functional>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <osquery/core/sql/table_row.h>
#include <osquery/core/tables.h>
#include <osquery/sql/dynamic_table_row.h>
#include <osquery/sql/virtual_table.h>
#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/json/json.h>

namespace osquery {

/**
 * @brief A TableRow that computes columns on demand.
 *
 * Table implementations register a callback per column. Eager callbacks run
 * once when the row is built (preserving the original side effect ordering
 * within generate()); lazy callbacks run on the first SQLite request for the
 * column through get_column() and their result is cached for the lifetime of
 * the row. Columns absent from the effective used set are never evaluated and
 * are reported as SQL NULL.
 *
 * A failure inside a callback is attributed to the column name in both the
 * log line and the thrown exception, so a column pruning regression can be
 * traced to the exact computation that failed.
 */
class LazyTableRow : public TableRow {
 public:
  using CellProvider = std::function<std::string()>;

  explicit LazyTableRow(boost::optional<UsedColumns> effective_columns)
      : effective_columns_(std::move(effective_columns)) {}

  /**
   * Register a column that is evaluated immediately, while generate() is
   * still on the stack and the original computation ordering matters.
   */
  void setColumn(const std::string& name, CellProvider provider) {
    if (!isRequired(name)) {
      return;
    }
    try {
      values_[name] = provider();
      ++computed_;
      if (metrics_) {
        ++metrics_->columns_computed;
      }
    } catch (const std::exception& e) {
      throwColumnError(name, e);
    }
  }

  /**
   * Register a column whose computation is deferred until SQLite actually
   * requests it. Unrequested columns incur zero cost.
   */
  void setLazyColumn(const std::string& name, CellProvider provider) {
    if (!isRequired(name)) {
      return;
    }
    providers_[name] = std::move(provider);
  }

  /// Whether the column belongs to the effective used set of the scan.
  bool isRequired(const std::string& name) const {
    return !effective_columns_ ||
           effective_columns_->find(name) != effective_columns_->end();
  }

  /// Attach the per-scan metrics so lazy computations are counted as well.
  void setMetrics(std::shared_ptr<TableQueryMetrics> metrics) {
    metrics_ = std::move(metrics);
  }

  int get_rowid(sqlite_int64 default_value, sqlite_int64* pRowid) const override {
    auto rowid_it = values_.find("rowid");
    if (rowid_it != values_.end()) {
      auto exp = tryTo<long long>(rowid_it->second, 10);
      if (exp.isError()) {
        return SQLITE_ERROR;
      }
      *pRowid = exp.take();
    } else {
      *pRowid = default_value;
    }
    return SQLITE_OK;
  }

  int get_column(sqlite3_context* ctx,
                 sqlite3_vtab* pVtab,
                 int col) override {
    auto* virtual_table = static_cast<VirtualTable*>(pVtab);
    if (col >= static_cast<int>(virtual_table->content->columns.size())) {
      return SQLITE_ERROR;
    }

    std::string column_name =
        std::get<0>(virtual_table->content->columns[col]);
    auto type = std::get<1>(virtual_table->content->columns[col]);
    if (virtual_table->content->aliases.count(column_name)) {
      auto target = virtual_table->content->aliases.at(column_name);
      column_name = std::get<0>(virtual_table->content->columns[target]);
      type = std::get<1>(virtual_table->content->columns[target]);
    }

    if (!isRequired(column_name)) {
      sqlite3_result_null(ctx);
      return SQLITE_OK;
    }

    evaluate(column_name);
    auto value_it = values_.find(column_name);
    if (value_it == values_.end()) {
      sqlite3_result_null(ctx);
      return SQLITE_OK;
    }

    const auto& value = value_it->second;
    if (type == TEXT_TYPE || type == BLOB_TYPE) {
      sqlite3_result_text(
          ctx, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
    } else if (value.empty() &&
               (type == INTEGER_TYPE || type == BIGINT_TYPE ||
                type == UNSIGNED_BIGINT_TYPE || type == DOUBLE_TYPE)) {
      sqlite3_result_null(ctx);
    } else if (type == INTEGER_TYPE) {
      auto parsed = tryTo<long>(value, 0);
      if (parsed.isError()) {
        sqlite3_result_null(ctx);
      } else {
        sqlite3_result_int(ctx, parsed.take());
      }
    } else if (type == BIGINT_TYPE || type == UNSIGNED_BIGINT_TYPE) {
      auto parsed = tryTo<long long>(value, 0);
      if (parsed.isError()) {
        sqlite3_result_null(ctx);
      } else {
        sqlite3_result_int64(ctx, parsed.take());
      }
    } else if (type == DOUBLE_TYPE) {
      char* end = nullptr;
      double parsed = strtod(value.c_str(), &end);
      if (end == nullptr || end == value.c_str() || *end != '\0') {
        sqlite3_result_null(ctx);
      } else {
        sqlite3_result_double(ctx, parsed);
      }
    } else {
      sqlite3_result_null(ctx);
    }
    return SQLITE_OK;
  }

  Status serialize(JSON& doc, rapidjson::Value& obj) const override {
    ensureAllRegistered();
    for (const auto& entry : values_) {
      doc.addRef(entry.first, entry.second, obj);
    }
    return Status::success();
  }

  TableRowHolder clone() const override {
    auto clone = std::make_unique<LazyTableRow>(effective_columns_);
    clone->values_ = values_;
    clone->providers_ = providers_;
    clone->computed_ = computed_;
    clone->metrics_ = metrics_;
    return TableRowHolder(clone.release());
  }

  operator Row() const override {
    ensureAllRegistered();
    Row result;
    for (const auto& entry : values_) {
      result[entry.first] = entry.second;
    }
    return result;
  }

  /// Number of distinct column computations performed for this row.
  std::size_t computedCount() const {
    return computed_;
  }

 private:
  [[noreturn]] static void throwColumnError(const std::string& name,
                                            const std::exception& e) {
    throw std::runtime_error("column '" + name +
                             "' computation failed: " + e.what());
  }

  void ensureAllRegistered() const {
    std::vector<std::string> names;
    names.reserve(providers_.size());
    for (const auto& entry : providers_) {
      names.push_back(entry.first);
    }
    for (const auto& name : names) {
      evaluate(name);
    }
  }

  void evaluate(const std::string& name) const;

  /// Effective used columns; unset means every column is required.
  boost::optional<UsedColumns> effective_columns_;

  /// Materialized column values.
  mutable std::unordered_map<std::string, std::string> values_;

  /// Deferred column computations.
  mutable std::unordered_map<std::string, CellProvider> providers_;

  /// Shared per-scan counters, optional and only used by instrumented tables.
  std::shared_ptr<TableQueryMetrics> metrics_;

  /// Count of computations performed on this row instance.
  mutable std::size_t computed_{0};

  /// Guards lazy evaluation when a row is shared across cursors.
  mutable std::mutex evaluate_mutex_;

  friend class LazyTableRowHolder;
};

/// Builder sugar mirroring make_table_row().
class LazyTableRowHolder {
 public:
  explicit LazyTableRowHolder(
      boost::optional<UsedColumns> effective_columns = boost::none)
      : row(new LazyTableRow(std::move(effective_columns))), ptr(row) {}

  operator TableRowHolder&&() {
    return std::move(ptr);
  }

  LazyTableRow* operator->() {
    return row;
  }

  const LazyTableRow* operator->() const {
    return row;
  }

 private:
  LazyTableRow* row;
  TableRowHolder ptr;
};

inline LazyTableRowHolder makeLazyTableRow(
    boost::optional<UsedColumns> effective_columns = boost::none) {
  return LazyTableRowHolder(effective_columns);
}

} // namespace osquery
