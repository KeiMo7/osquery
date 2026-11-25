/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>

#include <osquery/config/config.h>
#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>
#include <osquery/sql/sqlite_util.h>
#include <osquery/sql/table_publication.h>
#include <osquery/utils/conversions/join.h>
#include <plugins/config/parsers/auto_constructed_tables.h>

#include <map>
#include <thread>
#include <unordered_set>

namespace rj = rapidjson;

namespace osquery {

namespace {

struct ATCCandidate {
  TableEntryPtr entry;
  std::shared_ptr<ATCPlugin> plugin;
  std::string settings;
  std::string old_database_value;
  bool had_database_value{false};
  bool database_key_written{false};
};

struct AsyncATCCandidateReaper {
  std::vector<ATCCandidate>* candidates;

  explicit AsyncATCCandidateReaper(std::vector<ATCCandidate>* value)
      : candidates(value) {}

  ~AsyncATCCandidateReaper() {
    if (candidates == nullptr || candidates->empty()) {
      return;
    }

    std::thread([held = std::move(*candidates)]() mutable {
      (void)held;
    }).detach();
  }
};

} // namespace

TableAttributes ATCPlugin::attributes() const {
  return table_attributes_;
}

void ATCPlugin::setActive() {
  table_attributes_ = TableAttributes::NONE;
}

TableRows ATCPlugin::generate(QueryContext& context) {
  TableRows result;
  std::vector<std::string> paths;
  auto s = resolveFilePattern(path_, paths);
  if (!s.ok()) {
    LOG(WARNING) << "ATC Table: Could not glob: " << path_ << " skipping";
    return result;
  }
  for (const auto& path : paths) {
    s = getSqliteJournalMode(path);
    bool preserve_locking = false;
    if (!s.ok()) {
      VLOG(1) << "ATC Table: Unable to detect journal mode, applying default "
                 "locking policy"
              << " for path " << path;
    } else {
      preserve_locking = s.getMessage() == "wal";
    }
    s = genTableRowsForSqliteTable(
        path, sqlite_query_, result, preserve_locking);
    if (!s.ok()) {
      LOG(WARNING) << "ATC Table: Error Code: " << s.getCode()
                   << " Could not generate data: " << s.getMessage()
                   << " for path " << path;
    }
  }
  return result;
}

/// Remove these ATC tables from the registry and database
Status ATCConfigParserPlugin::removeATCTables(
    const std::set<std::string>& detach_tables) {
  auto registry_table = RegistryFactory::get().registry("table");
  std::set<std::string> failed_tables;
  for (const auto& table : detach_tables) {
    if (registry_table->exists(table)) {
      std::string value;
      if (getDatabaseValue(
              kPersistentSettings, kDatabaseKeyPrefix + table, value)
              .ok()) {
        registry_table->remove(table);
        PluginResponse resp;
        Registry::call(
            "sql", "sql", {{"action", "detatch"}, {"table", table}}, resp);
        VLOG(1) << "ATC table: " << table << " Removed";
      } else {
        failed_tables.insert(table);
      }
    }
    deleteDatabaseValue(kPersistentSettings, kDatabaseKeyPrefix + table);
  }
  if (failed_tables.empty()) {
    return Status();
  }
  return Status(
      1, "Attempted to remove non ATC tables: " + join(failed_tables, ", "));
}

/// Get all ATC tables that should be registered from the database
std::set<std::string> ATCConfigParserPlugin::registeredATCTables() {
  std::vector<std::string> tables;
  scanDatabaseKeys(kPersistentSettings, tables, kDatabaseKeyPrefix);
  std::set<std::string> set_tables;

  for (const auto& table : tables) {
    set_tables.insert(table.substr(kDatabaseKeyPrefix.size()));
  }
  return set_tables;
}

Status ATCConfigParserPlugin::setUp() {
  VLOG(1) << "Removing stale ATC entries";
  std::vector<std::string> keys;
  scanDatabaseKeys(kPersistentSettings, keys, kDatabaseKeyPrefix);
  for (const auto& key : keys) {
    auto s = deleteDatabaseValue(kPersistentSettings, key);
    if (!s.ok()) {
      LOG(INFO) << "ATC table: Could not clear ATC key " << key
                << "from database";
    }
  }
  return Status();
}

Status ATCConfigParserPlugin::update(const std::string& source,
                                     const ParserConfig& config) {
  auto cv = config.find(kParserKey);
  if (cv == config.end() || !cv->second.doc().IsObject()) {
    return Status::success();
  }

  {
    auto doc = JSON::newObject();
    auto obj = doc.getObject();
    doc.copyFrom(cv->second.doc(), obj);
    doc.addCopy(kParserKey, obj);
    data_ = std::move(doc);
  }

  const auto& ac_tables = data_.doc()[kParserKey];
  auto tables = RegistryFactory::get().registry("table");
  auto registered = registeredATCTables();
  auto previous_snapshot = TablePublicationRegistry::snapshot();

  std::vector<ATCCandidate> candidates;
  AsyncATCCandidateReaper candidate_reaper(&candidates);
  std::set<std::string> configured_names;
  std::string content_hash = source;

  // Phase 1: parse every entry and perform all no-database validation. No
  // table is published until the complete candidate vector is available.
  for (const auto& ac_table : ac_tables.GetObject()) {
    if (!ac_table.name.IsString() || !ac_table.value.IsObject()) {
      // This entry is not formatted correctly.
      continue;
    }

    std::string table_name{ac_table.name.GetString()};
    configured_names.insert(table_name);
    registered.erase(table_name);
    auto params = ac_table.value.GetObject();

    std::string query{params.HasMember("query") && params["query"].IsString()
                          ? params["query"].GetString()
                          : ""};
    std::string path{params.HasMember("path") && params["path"].IsString()
                         ? params["path"].GetString()
                         : ""};
    std::string platform{params.HasMember("platform") &&
                                 params["platform"].IsString()
                             ? params["platform"].GetString()
                             : ""};

    if (query.empty() || path.empty()) {
      LOG(WARNING) << "ATC Table: Skipping " << table_name
                   << " because it is misconfigured (missing query or path)";
      continue;
    }

    if (!checkPlatform(platform)) {
      VLOG(1) << "ATC table: Skipping " << table_name
              << " because platform doesn't match";
      continue;
    }

    TableColumns columns;
    std::string columns_value;
    columns_value.reserve(256);
    bool duplicate_column = false;
    std::unordered_set<std::string> seen_columns;

    if (!params.HasMember("columns") || !params["columns"].IsArray()) {
      LOG(WARNING) << "ATC Table: Skipping " << table_name
                   << " because it is misconfigured (no columns)";
      continue;
    }

    std::string user_defined_path_column;

    for (const auto& column : params["columns"].GetArray()) {
      if (!column.IsString()) {
        LOG(WARNING) << "ATC Table: " << table_name
                     << " is misconfigured. (non-string column)";
        continue;
      }

      std::string column_name{column.GetString()};
      auto folded_name = boost::algorithm::to_lower_copy(column_name);
      if (!seen_columns.insert(folded_name).second) {
        duplicate_column = true;
        LOG(WARNING) << "ATC Table: Skipping " << table_name
                     << " because column " << column_name << " is duplicated";
        break;
      }

      if (boost::iequals(column_name, "path")) {
        user_defined_path_column = column_name;
      }

      columns.push_back(make_tuple(
          std::string(column.GetString()), TEXT_TYPE, ColumnOptions::DEFAULT));
      columns_value += std::string(column.GetString()) + ",";
    }

    if (duplicate_column) {
      continue;
    }

    if (!user_defined_path_column.empty()) {
      LOG(WARNING) << "ATC Table: " << table_name
                   << " is misconfigured. The configuration includes `"
                   << user_defined_path_column
                   << "`. This is a reserved column name";
    } else {
      // Add implicit path column
      columns.push_back(
          make_tuple(std::string("path"), TEXT_TYPE, ColumnOptions::DEFAULT));
      columns_value += "path,";
    }

    std::string table_settings{table_name + query + columns_value + path};
    content_hash += "|" + table_settings;

    std::string old_setting;
    bool had_database_value =
        getDatabaseValue(
            kPersistentSettings, kDatabaseKeyPrefix + table_name, old_setting)
            .ok();

    // A registry item without a corresponding atc.* key is a built-in/core or
    // otherwise non-ATC table. Refuse to overwrite it.
    if (tables->exists(table_name) && !had_database_value) {
      LOG(WARNING) << "ATC Table: " << table_name
                   << " overrides core table; Refusing registration";
      continue;
    }

    auto entry = std::make_shared<TableEntry>(
        table_name, nullptr, columns, TableAttributes::PENDING, 0, source);
    entry->query = query;
    entry->sql = query;
    entry->path = path;
    entry->requires_sqlite_source = true;

    std::string reason;
    auto validation = TablePublicationRegistry::validate(*entry, reason);
    if (!validation.ok()) {
      LOG(WARNING) << "ATC Table: Skipping " << table_name << ": " << reason;
      continue;
    }

    auto plugin = std::make_shared<ATCPlugin>(path, columns, query);
    entry->plugin = std::static_pointer_cast<TablePlugin>(plugin);
    entry->attributes = plugin->attributes();
    entry->after_attach_verification = [plugin]() { plugin->setActive(); };

    ATCCandidate candidate;
    candidate.entry = entry;
    candidate.plugin = plugin;
    candidate.settings = table_settings;
    candidate.old_database_value = old_setting;
    candidate.had_database_value = had_database_value;
    candidates.push_back(std::move(candidate));
  }

  // Phase 2: persist atc.* keys. A failed key write excludes only that entry
  // and removes the key it attempted to write.
  std::vector<TableEntryPtr> desired;
  desired.reserve(candidates.size());

  for (auto& candidate : candidates) {
    const auto& table_name = candidate.entry->name;
    auto status = setDatabaseValue(kPersistentSettings,
                                   kDatabaseKeyPrefix + table_name,
                                   candidate.settings);
    if (!status.ok()) {
      LOG(WARNING) << "ATC Table: " << table_name
                   << " could not write to database: " << status.getMessage();
      deleteDatabaseValue(kPersistentSettings, kDatabaseKeyPrefix + table_name);
      continue;
    }

    candidate.database_key_written = true;
    desired.push_back(candidate.entry);
  }

  TablePublicationStats publication_stats;
  std::vector<std::string> explicit_removals;
  for (const auto& old_item : previous_snapshot->tables) {
    const auto& old_entry = old_item.second;
    if (old_entry && old_entry->source == source &&
        configured_names.count(old_entry->name) == 0) {
      explicit_removals.push_back(old_entry->name);
    }
  }

  auto publish_status = TablePublicationRegistry::publish(
      desired, explicit_removals, content_hash, publication_stats);

  auto restore_database_keys = [&](const std::set<std::string>& names) {
    for (auto& candidate : candidates) {
      const auto& name = candidate.entry->name;
      if (names.count(name) == 0 || !candidate.database_key_written) {
        continue;
      }

      if (candidate.had_database_value) {
        setDatabaseValue(kPersistentSettings,
                         kDatabaseKeyPrefix + name,
                         candidate.old_database_value);
      } else {
        deleteDatabaseValue(kPersistentSettings, kDatabaseKeyPrefix + name);
      }
    }
  };

  if (publish_status.getCode() != 0 && publish_status.getCode() != 2) {
    LOG(INFO) << "ATC table publication failed: "
              << publish_status.getMessage();
    std::set<std::string> candidate_names;
    for (const auto& candidate : candidates) {
      candidate_names.insert(candidate.entry->name);
    }
    restore_database_keys(candidate_names);
    return publish_status;
  }

  if (publish_status.getCode() == 0) {
    // Restore keys for entries that were written locally but did not become
    // effective publication entries because of a conflict/registry failure.
    std::set<std::string> published_names(
        publication_stats.published_tables.begin(),
        publication_stats.published_tables.end());
    std::set<std::string> unsuccessful_names;
    for (const auto& candidate : candidates) {
      const auto& name = candidate.entry->name;
      if (published_names.count(name) == 0) {
        unsuccessful_names.insert(name);
      }
    }
    restore_database_keys(unsuccessful_names);

    for (const auto& name : publication_stats.published_tables) {
      for (auto& candidate : candidates) {
        if (candidate.entry->name == name) {
          candidate.plugin->setActive();
          break;
        }
      }
      LOG(INFO) << "ATC table: " << name << " Registered";
    }
  }

  // Remove atc.* keys and registry ownership for tables absent from this
  // source. Preserve tables owned by another configuration source.
  std::set<std::string> keys_to_remove;
  for (const auto& table_name : registered) {
    auto old_entry = previous_snapshot->find(table_name);
    if (old_entry && !old_entry->source.empty() &&
        old_entry->source != source) {
      continue;
    }
    keys_to_remove.insert(table_name);
  }

  if (!keys_to_remove.empty()) {
    VLOG(1)
        << "Removing any ATC tables that were removed in this configuration "
           "change";
    removeATCTables(keys_to_remove);
  }

  return Status::success();
}

REGISTER_INTERNAL(ATCConfigParserPlugin,
                  "config_parser",
                  "auto_constructed_tables");
} // namespace osquery
