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
#include <osquery/tables/events/windows/sysmon_process_events.h>

namespace osquery {

    REGISTER(SysmonEtwProcessEventsSubscriber, "event_subscriber", "sysmon_process_events");

    Status SysmonEtwProcessEventsSubscriber::init() {
        auto sc = createSubscriptionContext();

        // TODO: We will have to pass on task_id (ProcessCreate), such
        // that publisher can identify and send only events specific to 
        // this subscriber. May be name should suffice as well. i.e. sysmon_process_events
        subscribe(&SysmonEtwProcessEventsSubscriber::Callback, sc);

        return Status::success();
    }

    Status SysmonEtwProcessEventsSubscriber::Callback(const ECRef& event,
            const SCRef&) {
        //TODO: Add rows in batches to improve performance
        Row row;
        // warning C4996: 'osquery::EventSubscriberPlugin::add': Group events together and use addBatch() instead.
        generateRow(row, event);
        add(row);

        return Status::success();

    }

    void SysmonEtwProcessEventsSubscriber::generateRow(Row& row, const ECRef& event) {
        row = {};

#ifdef SYSMON_PRINT_EVENT
        printf("\n\nxxxxxxxxxxxxxx BEGIN: process create event subscriber xxxxxxxxxx.\n");
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
        printf("xxxxxxxxxxxxxx END: process create event subscriber xxxxxxxxxx.\n");
#endif

        //  Taken from sysmon manifest file
        //  <template tid = "ProcessCreate(rule:ProcessCreate)Args_V5">
        //	<data name = "RuleName" inType = "win:UnicodeString" / >
        //	<data name = "UtcTime" inType = "win:UnicodeString" / >
        //	<data name = "ProcessGuid" inType = "win:GUID" / >
        //	<data name = "ProcessId" inType = "win:UInt32" / >
        //	<data name = "Image" inType = "win:UnicodeString" / >
        //	<data name = "FileVersion" inType = "win:UnicodeString" / >
        //	<data name = "Description" inType = "win:UnicodeString" / >
        //	<data name = "Product" inType = "win:UnicodeString" / >
        //	<data name = "Company" inType = "win:UnicodeString" / >
        //	<data name = "OriginalFileName" inType = "win:UnicodeString" / >
        //	<data name = "CommandLine" inType = "win:UnicodeString" / >
        //	<data name = "CurrentDirectory" inType = "win:UnicodeString" / >
        //	<data name = "User" inType = "win:UnicodeString" / >
        //	<data name = "LogonGuid" inType = "win:GUID" / >
        //	<data name = "LogonId" inType = "win:HexInt64" / >
        //	<data name = "TerminalSessionId" inType = "win:UInt32" / >
        //	<data name = "IntegrityLevel" inType = "win:UnicodeString" / >
        //	<data name = "Hashes" inType = "win:UnicodeString" / >
        //	<data name = "ParentProcessGuid" inType = "win:GUID" / >
        //	<data name = "ParentProcessId" inType = "win:UInt32" / >
        //	<data name = "ParentImage" inType = "win:UnicodeString" / >
        //	<data name = "ParentCommandLine" inType = "win:UnicodeString" / >
        //</template>
    }

    SysmonEtwProcessEventsSubscriber::~SysmonEtwProcessEventsSubscriber(){}
} // namespace osquery
