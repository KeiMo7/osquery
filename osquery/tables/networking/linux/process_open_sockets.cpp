/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/sql/column_dependencies.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/filesystem/linux/proc.h>
#include <osquery/sql/lazy_table_row.h>

namespace osquery {
namespace tables {

// The address/port pairs are produced from the same parsed /proc/net entries;
// declaring them as a group prevents splitting one parse across partially
// requested rows while still allowing path-only UNIX socket queries to skip
// the network fields entirely.
OSQUERY_REGISTER_COLUMN_DEPENDENCIES(
    process_open_sockets,
    {"local_address", {"local_port"}},
    {"local_port", {"local_address"}},
    {"remote_address", {"remote_port"}},
    {"remote_port", {"remote_address"}},
    {"family", {"protocol"}},
    {"protocol", {"family"}});

TableRows genOpenSockets(QueryContext& context) {
  Status status;
  TableRows results;

  /*
   * If filtering by pid, restrict results to the list of pids provided
   * otherwise query all pids from the system and also report on sockets without
   * an associated pid.
   */
  std::set<std::string> pids;
  if (context.constraints["pid"].exists(EQUALS)) {
    pids = context.constraints["pid"].getAll(EQUALS);
  }

  bool pid_filter = !(pids.empty() ||
                      std::find(pids.begin(), pids.end(), "-1") != pids.end());

  if (!pid_filter) {
    pids.clear();
    status = osquery::procProcesses(pids);
    if (!status.ok()) {
      VLOG(1) << "Failed to acquire pid list: " << status.what();
      return results;
    }
  }

  /* Data for this table is fetched from 3 different sources and correlated.
   *
   * 1. Collect all sockets associated with each pid by going through all files
   * under /proc/<pid>/fd and search for links of the type socket:[<inode>].
   * Extract the inode and fd (filename) and index it by inode number. The inode
   * can then be used to correlate pid and fd with the socket information
   * collected on step 3. The map generated in this step will only contain
   * sockets associated with pids in the list, so it will also be used to filter
   * the sockets later if pid_filter is set.
   *
   * 2. Collect the inode for the network namespace associated with each pid.
   * Every time a new namespace is found execute step 3 to get socket basic
   * information.
   *
   * 3. Collect basic socket information for all sockets under a specifc network
   * namespace. This is done by reading through files under /proc/<pid>/net for
   * the first pid we find in a certain namespace. Notice this will collect
   * information for all sockets on the namespace not only for sockets
   * associated with the specific pid, therefore only needs to be run once. From
   * this step we collect the inodes of each of the sockets, and will use that
   * to correlate the socket information with the information collect on steps
   * 1 and 2.
   */

  /* Use a set to record the namespaces already processed */
  std::set<ino_t> netns_list;
  SocketInodeToProcessInfoMap inode_proc_map;
  SocketInfoList socket_list;
  for (const auto& pid : pids) {
    /* Step 1 */
    status = procGetSocketInodeToProcessInfoMap(pid, inode_proc_map);
    if (!status.ok()) {
      VLOG(1) << "Results for process_open_sockets might be incomplete. Failed "
                 "to acquire socket inode to process map for pid "
              << pid << ": " << status.what();
    }

    /* Step 2 */
    ino_t ns;
    ProcessNamespaceList namespaces;
    status = procGetProcessNamespaces(pid, namespaces, {"net"});
    if (status.ok()) {
      ns = namespaces["net"];
    } else {
      /* If namespaces are not available we allways set ns to 0 and step 3 will
       * run once for the first pid in the list.
       */
      ns = 0;
      VLOG(1) << "Results for the process_open_sockets might be incomplete."
                 "Failed to acquire network namespace information for process "
                 "with pid "
              << pid << ": " << status.what();
    }

    if (netns_list.count(ns) == 0) {
      netns_list.insert(ns);

      /* Step 3 */
      for (const auto& pair : kLinuxProtocolNames) {
        status = procGetSocketList(AF_INET, pair.first, ns, pid, socket_list);
        if (!status.ok()) {
          VLOG(1)
              << "Results for process_open_sockets might be incomplete. Failed "
                 "to acquire basic socket information for AF_INET "
              << pair.second << ": " << status.what();
        }

        status = procGetSocketList(AF_INET6, pair.first, ns, pid, socket_list);
        if (!status.ok()) {
          VLOG(1)
              << "Results for process_open_sockets might be incomplete. Failed "
                 "to acquire basic socket information for AF_INET6 "
              << pair.second << ": " << status.what();
        }
      }
      status = procGetSocketList(AF_UNIX, IPPROTO_IP, ns, pid, socket_list);
      if (!status.ok()) {
        VLOG(1)
            << "Results for process_open_sockets might be incomplete. Failed "
               "to acquire basic socket information for AF_UNIX: "
            << status.what();
      }

      // protocol is 0, we want all protocols here.
      status = procGetSocketList(AF_PACKET, 0, ns, pid, socket_list);
      if (!status.ok()) {
        VLOG(1)
            << "Results for process_open_sockets might be incomplete. Failed "
               "to acquire basic socket information for AF_PACKET: "
            << status.what();
      }
    }
  }

  /* Finally correlate all the information. Go through all the sockets
   * collected on step 3 and correlate that with the pid and fd collected from
   * step 1. If filtering only take sockets for which the inode is available on
   * the inode to process information map.
   */
  for (const auto& info : socket_list) {
    auto r = makeLazyTableRow(context.effectiveColsUsed);
    r->setMetrics(context.metrics);
    auto proc_it = inode_proc_map.find(info.socket);
    if (proc_it != inode_proc_map.end()) {
      const auto pid = proc_it->second.pid;
      const auto fd = proc_it->second.fd;
      r->setColumn("pid", [=] { return pid; });
      r->setColumn("fd", [=] { return fd; });
    } else if (!pid_filter) {
      r->setColumn("pid", [] { return std::string("-1"); });
      r->setColumn("fd", [] { return std::string("-1"); });
    } else {
      /* If we're filtering by pid we only care about sockets associated with
       * pids on the list.*/
      continue;
    }

    const auto socket = info.socket;
    const auto family = info.family;
    const auto protocol = info.protocol;
    const auto local_address = info.local_address;
    const auto local_port = info.local_port;
    const auto remote_address = info.remote_address;
    const auto remote_port = info.remote_port;
    const auto unix_path = info.unix_socket_path;
    const auto state = info.state;
    const auto net_namespace = info.net_ns;

    r->setColumn("socket", [=] { return socket; });
    r->setLazyColumn("family", [=] { return std::to_string(family); });
    r->setLazyColumn("protocol", [=] { return std::to_string(protocol); });
    r->setLazyColumn("local_address", [=] { return local_address; });
    r->setLazyColumn("local_port",
                     [=] { return std::to_string(local_port); });
    r->setLazyColumn("remote_address", [=] { return remote_address; });
    r->setLazyColumn("remote_port",
                     [=] { return std::to_string(remote_port); });
    r->setLazyColumn("path", [=] { return unix_path; });
    r->setLazyColumn("state", [=] { return state; });
    r->setLazyColumn("net_namespace",
                     [=] { return std::to_string(net_namespace); });

    results.push_back(static_cast<TableRowHolder&&>(r));
    context.recordRowGenerated();
  }

  return results;
}
} // namespace tables
} // namespace osquery
