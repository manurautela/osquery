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

// #define SYSMON_PRINT_EVENT 0

// Sysmon task id taken from manifest
#define SysmonProcessCreate                            1
#define SysmonFilecreationtimechanged                  2
#define SysmonNetworkconnectiondetected                3
#define Sysmonservicestatechanged                      4
#define SysmonProcessterminated                        5
#define SysmonDriverloaded                             6
#define SysmonImageloaded                              7
#define SysmonCreateRemoteThreaddetected               8
#define SysmonRawAccessReaddetected                    9
#define SysmonProcessaccessed                          10
#define SysmonFilecreated                              11
#define SysmonRegistryobjectaddedordeleted             12
#define SysmonRegistryvalueset                         13
#define SysmonRegistryobjectrenamed                    14
#define SysmonFilestreamcreated                        15
#define Sysmonconfigstatechanged                       16
#define SysmonPipeCreated                              17
#define SysmonPipeConnected                            18
#define SysmonWmiEventFilteractivitydetected           19
#define SysmonWmiEventConsumeractivitydetected         20
#define SysmonWmiEventConsumerToFilteractivitydetected 21
#define SysmonDnsquery                                 22
#define SysmonFileDelete                               23
#define SysmonClipboardchanged                         24
#define SysmonProcessTampering                         25

    /**
     * @brief Subscription details for Sysmon ETW Traces
     *
     * This context is specific to the Sysmon ETW traces.
     * Different subscribers like process, registry, dns
     * and others based on taskId of sysmon events may
     * subscribe and receive the events from publisher.
     */
    struct SysmonEtwSubscriptionContext : public SubscriptionContext {
        // This will allow publisher to selectively events to subscribers
        // that they wish to handle
        USHORT taskId;
        private:
            friend class SysmonEtwEventPublisher;
    };

    /**
     * @brief Event details for SysmonEtwEventPublisher events.
     *
     * It is the responsibility of the subscriber to understand the best
     * way in which to parse the event data. The publisher will parse
     * the events and handover to the appropriate subscriber based on
     * taskId e.g. ProcessCreate, ProcessTerminate, PipeConnected etc.
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

        /// event data based on taskId
        std::map<std::wstring, std::wstring> eventData;

        /// GUID associated with the ETW trace provider
        USHORT taskId;
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
     * publisher run loop, we decide based on event taskId, which subscribor
     * to invoke. Then publisher hands over that event to intended subscribor.
     */
    class SysmonEtwEventPublisher
        : public EventPublisher<SysmonEtwSubscriptionContext, SysmonEtwEventContext> {

            DECLARE_PUBLISHER("SysmonEtwEventPublisher");

        public:
            bool shouldFire(const SysmonEtwSubscriptionContextRef& sc,
                    const SysmonEtwEventContextRef& ec) const override;

            void configure() override;

            void tearDown() override;

            void stopPrevEtwSession();

            /// The calling for beginning the thread's run loop.
            Status run() override;

            static bool WINAPI processEtwRecord(PEVENT_RECORD pEvent);
            static DWORD WINAPI sysmonProcessTraceThread(LPVOID param);

        private:
            /// Ensures that all Windows event log subscriptions are removed
            void stop() override;

            TRACEHANDLE sessionHandle_ = { 0 };
            TRACEHANDLE hTrace_        = { 0 };

        public:
            // friend class SysmonEtwTests;
        };
} // namespace osquery
