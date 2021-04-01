/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */
#pragma once

#include <osquery/events/eventsubscriber.h>
#include <osquery/events/windows/sysmon_etw.h>

namespace osquery {

class SysmonEtwDnsqueryEventsSubscriber
: public EventSubscriber<SysmonEtwEventPublisher> {
    public:
        Status init() override;

        virtual ~SysmonEtwDnsqueryEventsSubscriber() override;

        Status Callback(const ECRef& event, const SCRef& subscription);

        static void generateRow(Row& row, const ECRef& event);
};
} // namespace osquery
