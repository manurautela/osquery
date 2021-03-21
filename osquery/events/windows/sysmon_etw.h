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
     * Different subscribers like process, registry, dns
     * and others based on task_id of sysmon events may
     * subscribe and receive the events from publisher.
     */
    struct SysmonEtwSubscriptionContext : public SubscriptionContext {
        private:
            friend class SysmonEtwEventPublisher;
    };

    /**
     * @brief Event details for SysmonEtwEventPublisher events.
     *
     * It is the responsibility of the subscriber to understand the best
     * way in which to parse the event data. The publisher will parse
     * the events and handover to the appropriate subscriber based on
     * task_id e.g. ProcessCreate, ProcessTerminate, PipeConnected etc.
     * The subscriber further does use this for row population.
     */
    struct SysmonEtwEventContext : public EventContext {
        public:
        /// Event Metadata associated with the record
        ULONG pid;

        USHORT eventId;

        UCHAR level;

        UCHAR channel;

        ULONGLONG uptime;

        ULONGLONG timestamp;

        /// event data based on task_id
        std::map<std::wstring, std::wstring> eventData;

        /// GUID associated with the ETW trace provider
        GUID etwProviderGuid;
        std::string ProviderGuid;
    };

    using SysmonEtwEventContextRef        = std::shared_ptr<SysmonEtwEventContext>;
    using SysmonEtwSubscriptionContextRef = std::shared_ptr<SysmonEtwSubscriptionContext>;

    /**
     * @brief A Sysmon Etw Event Log Publisher
     *
     * This EventPublisher allows EventSubscriber's to subscribe to Sysmon Etw
     * events in real-time. Note we create a single trace session for Sysmon
     * and pass on events received to appropriate subscribers. Within the
     * publisher run loop, we decide based on event task_id, which subscribor
     * to invoke. Then publisher hands over that event to intended subscribor.
     */
    class SysmonEtwEventPublisher
        : public EventPublisher<SysmonEtwSubscriptionContext, SysmonEtwEventContext> {

            DECLARE_PUBLISHER("SysmonEtwEventPublisher");

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

            /// Note: we simply maintain a single trace session at publisher side
            //  TODO: Revisit and see if this can be optmized if needed.
            TRACEHANDLE sessionHandle_ = { 0 };
            TRACEHANDLE hTrace_        = { 0 };
            EVENT_TRACE_PROPERTIES* sessionProperties_;

        public:
            // friend class SysmonEtwTests;
        };
} // namespace osquery
