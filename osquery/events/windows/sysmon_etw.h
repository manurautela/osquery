/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <windows.h>
#include <evntcons.h>
#include <evntrace.h>
#include <memory>
#include <tdh.h>

#include <osquery/events/eventpublisher.h>

namespace osquery {

    /**
     * @brief Subscription details for Sysmon ETW Traces
     *
     * This context is specific to the Sysmon ETW traces.
     */
    struct SysmonEtwSubscriptionContext : public SubscriptionContext {
        // TODO: This will be based on subscriber type like process events. We
        // may have a context mentioning what all filters subscriber wishes to
        // set on the events that we receive from sysmon's etw trace session.
        // Accordingly we can apply them on the trace session and hand over the
        // events received via eventcallback back to subscribor.
        // guid, trace_name, keywords may be.

        private:
            friend class SysmonEtwPublisher;
    };

    /**
     * @brief Event details for WindowsEventLogEventPublisher events.
     *
     * It is the responsibility of the subscriber to understand the best
     * way in which to parse the event data. The publisher will convert the
     * Event Log record into a boost::property_tree, and return the tree to
     * the subscriber for further parsing and row population.
     */
    struct SysmonEtwEventContext : public EventContext {
        /// Event Metadata associated with the record
        unsigned long pid;

        unsigned short eventId;

        unsigned char level;

        unsigned char channel;

        unsigned long long uptime;

        unsigned long long timestamp;

        /// Relevant event data
        std::map<std::string, std::string> eventData;

        /// GUID associated with the ETW trace provider
        GUID etwProviderGuid;
    };


    using SysmonEtwEventContextRef  = std::shared_ptr<SysmonEtwEventContext>; using
        SysmonEtwSubscriptionContextRef = std::shared_ptr<SysmonEtwSubscriptionContext>;

    /**
     * @brief A Windows Event Log Publisher
     *
     * This EventPublisher allows EventSubscriber's to subscribe to Sysmon
     * Etw Logs. Note we create a single trace session for Sysmon and
     * funnel all the events received back to various subscribors.
     * Within the publisher run loop, we decide based on event opcode
     * which subscribor to call to. Then publisher passes on that event
     * data back to subscribor accordingly.
     */
    class SysmonEtwEventPublisher
        : public EventPublisher<SysmonEtwSubscriptionContext, SysmonEtwEventContext> {

            // DECLARE_PUBLISHER("sysmon_etw");

            public:
            ///
            bool shouldFire(const SysmonEtwSubscriptionContextRef& sc,
                    const SysmonEtwEventContextRef& ec) const override;

            void configure() override;

            void tearDown() override;

            /// The calling for beginning the thread's run loop.
            Status run() override;

            static bool WINAPI processEtwRecord(PEVENT_RECORD pEvent);

            private:
            /// we don't really have multiple traces(session)
            std::vector<GUID> providerGuids_;

            /// Map of trace name, to the GUID/Handle pair for ease of access
            std::map<std::string, std::pair<GUID, TRACEHANDLE>> etw_handles_;

            public:
            // friend class SysmonEtwTests;
        };
} // namespace osquery
