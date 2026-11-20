/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/sql/lazy_table_row.h>

#include <osquery/logger/logger.h>

#include <stdexcept>

namespace osquery {

void LazyTableRow::evaluate(const std::string& name) const {
  auto provider_it = providers_.find(name);
  if (provider_it == providers_.end()) {
    // Already materialized or never registered.
    return;
  }

  std::lock_guard<std::mutex> lock(evaluate_mutex_);
  provider_it = providers_.find(name);
  if (provider_it == providers_.end()) {
    return;
  }

  try {
    values_[name] = provider_it->second();
  } catch (const std::exception& e) {
    LOG(ERROR) << "Exception while computing column '" << name
               << "' lazily: " << e.what();
    providers_.erase(provider_it);
    throw std::runtime_error("column '" + name +
                             "' computation failed: " + e.what());
  }

  providers_.erase(provider_it);
  ++computed_;
  if (metrics_) {
    ++metrics_->columns_computed;
  }
}

} // namespace osquery
