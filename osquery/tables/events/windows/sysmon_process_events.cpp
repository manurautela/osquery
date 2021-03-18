/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/events/eventsubscriber.h>
#include <osquery/events/windows/sysmon_etw.h>
#include <osquery/tables/events/windows/sysmon_process_events.h>


namespace osquery {

    Status SysmonEtwProcessEventsSubscriber::init() {
        auto sc = createSubscriptionContext();

        subscribe(&SysmonEtwProcessEventsSubscriber::Callback, sc);

        return Status::success();
    }

    Status SysmonEtwProcessEventsSubscriber::Callback(const ECRef& event, const SCRef&) {
        // call generateRow() and pass event_data received from publisher received in event
        return Status::success();
    }

    void SysmonEtwProcessEventsSubscriber::generateRow(Row& row, const ProcessEventData& event_data) {
        // row = {};
        // TODO: Fill in row with data from event_data
    }

    SysmonEtwProcessEventsSubscriber::~SysmonEtwProcessEventsSubscriber(){}
} // namespace osquery
