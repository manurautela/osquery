/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/events/eventsubscriber.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/conversions/windows/strings.h>

#include <osquery/events/windows/sysmon_etw.h>
#include <osquery/tables/events/windows/sysmon_process_terminate_events.h>

namespace osquery {

    REGISTER(SysmonEtwProcessTerminateEventsSubscriber, "event_subscriber", "sysmon_process_terminate_events");

    Status SysmonEtwProcessTerminateEventsSubscriber::init() {
        auto sc = createSubscriptionContext();
        sc->taskId = SysmonProcessterminated;

        // We pass on taskId (ProcessTerminate), such that publisher can
        // identify and send only events specific to this subscriber.
        subscribe(&SysmonEtwProcessTerminateEventsSubscriber::Callback, sc);

        return Status::success();
    }

    Status SysmonEtwProcessTerminateEventsSubscriber::Callback(const ECRef& event,
            const SCRef&) {
        //TODO: Add rows in batches to improve performance
        Row row;
        // warning C4996: 'osquery::EventSubscriberPlugin::add': Group events together and use addBatch() instead.
        generateRow(row, event);
        add(row);

        return Status::success();
    }

    void SysmonEtwProcessTerminateEventsSubscriber::generateRow(Row& row, const ECRef& event) {
        row = {};

#ifdef SYSMON_PRINT_EVENT
        printf("\n\nxxxxxxxxxxxxxx BEGIN: process terminate event subscriber xxxxxxxxxx.\n");
        printf("pid: %d\n", event->pid);
        printf("provider_guid: %s\n", event->ProviderGuid.c_str());
#endif

        for(const auto& [key, value] : event->eventData) {
#ifdef SYSMON_PRINT_EVENT
            printf("%ws : %ws\n", key.c_str(), value.c_str());
#endif
            row[wstringToString(key)] = wstringToString(value);
        }

#ifdef SYSMON_PRINT_EVENT
        printf("xxxxxxxxxxxxxx END: process terminate event subscriber xxxxxxxxxx.\n");
#endif
     }

    SysmonEtwProcessTerminateEventsSubscriber::~SysmonEtwProcessTerminateEventsSubscriber(){}
} // namespace osquery
