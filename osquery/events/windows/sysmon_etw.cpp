/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */


#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/events/windows/sysmon_etw.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>


namespace osquery {

    REGISTER(SysmonEtwEventPublisher,
            "event_publisher",
            "sysmon_etw");

    const std::string kOsqueryEtwSessioName = "Microsoft-Windows-Sysmon";

    void SysmonEtwEventPublisher::configure() {
        tearDown();

        /// TODO: Add the logic to setup user trace session via krabs library
    }

    bool WINAPI SysmonEtwEventPublisher::processEtwRecord(PEVENT_RECORD pEvent) {
        /// TODO: this call back is set in user trace created in configure()
        // Once configured receives the event on the session via sysmon provider
        // This is the core function which delivers the event to the appropriate
        // subscriber based on opcode (event type) to either process, image load,
        // registry or dnsquery subscribor. Passing along the event data on fire()
        return true;
    }

    Status SysmonEtwEventPublisher::run() {
        // setup the callback function for EVENT_RECORD to processEtwRecord
        return Status::success();
    }


    void SysmonEtwEventPublisher::tearDown() {
        // Cleanup any subscriber specific context here
    }

    bool SysmonEtwEventPublisher::shouldFire(const SysmonEtwSubscriptionContextRef& sc,
            const SysmonEtwEventContextRef& ec) const {
        // In our case we always fire the event, provided there is atleast one subscribor
        return true;
    }

} // namespace osquery


