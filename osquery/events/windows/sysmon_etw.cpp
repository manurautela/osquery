/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#define INITGUID

#include <osquery/events/eventfactory.h>
#include <osquery/events/windows/sysmon_etw.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>

#include <combaseapi.h>

#define OSQUERY_SYSMON_LOGGER_NAME  L"osquery-sysmon-etw-trace"


namespace osquery {

    REGISTER(SysmonEtwEventPublisher,
            "event_publisher",
            "SysmonEtwEventPublisher");

    const std::string kOsquerySysmonEtwSessionName = "osquery-sysmon-etw-trace";

    static const GUID kOsquerySessionGuid = {
        0x22377e0a,
        0x63b0,
        0x4f43,
        {0xa8, 0x24, 0x4b, 0x35, 0x54, 0xac, 0x89, 0x85}};


    // Sysmon etw trace Microsoft-Windows-Sysmon setup
    // Name: Microsoft-Windows-Sysmon
    // Provider Guid : {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
    // Level: 255
    // KeywordsAll : 0x8000000000000000 (Microsoft-Windows-Sysmon/Operational)
    //
    // Provider guid that we may want to enable on a trace session
    struct __declspec(uuid("{5770385F-C22A-43E0-BF4C-06F5698FFBD9}")) sysmon_guid_holder;
    static const GUID sysmon_provider_guid = __uuidof(sysmon_guid_holder);

    // This is used to generate unique trace guid at runtime
    inline GUID randomGuid() {
        GUID tmpGuid;
        CoCreateGuid(&tmpGuid);
        return tmpGuid;
    }


    void SysmonEtwEventPublisher::configure() {
        // tearDown();

        // TODO: See if we need any details from subscriber during initial
        // trace setup. And adjust the trace session accordingly.
        //for (const auto& sub : subscriptions_) {
        //  auto sc = getSubscriptionContext(sub->context);
        //}

        // Allocate buffer for session properties of the trace
        unsigned long buffSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(OSQUERY_SYSMON_LOGGER_NAME);

        auto sessionProperties_ = static_cast<EVENT_TRACE_PROPERTIES*>(malloc(buffSize));

        ZeroMemory(sessionProperties_, buffSize);
        sessionProperties_->Wnode.BufferSize = buffSize;
        sessionProperties_->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        sessionProperties_->Wnode.ClientContext = 1;
        sessionProperties_->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        sessionProperties_->MaximumFileSize = 1;
        sessionProperties_->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        // TODO: should we keep a static GUID
        sessionProperties_->Wnode.Guid = randomGuid();

        TRACEHANDLE sessionHandle = 0;
        auto status = StartTrace(&sessionHandle, OSQUERY_SYSMON_LOGGER_NAME,sessionProperties_);

        // If the trace already exists, stop it and restart.
        if (status == ERROR_ALREADY_EXISTS) {
            printf("Stopping trace sesson before starting a new one...\n");
            stop();

            status = StartTrace((PTRACEHANDLE)&sessionHandle,
                    OSQUERY_SYSMON_LOGGER_NAME,
                    sessionProperties_);
        }

        if (sessionHandle == 0) {
            LOG(WARNING) << "Failed to start trace for provider with " << status;
            goto cleanup;
        }

        // Enable sysmon provider for the trace session created previously.
        // Such that we can receive the events on the enabled provider emits based
        // on the trace configuration.
        ENABLE_TRACE_PARAMETERS parameters;
        ZeroMemory(&parameters, sizeof(parameters));

        parameters.ControlFlags = 0;
        parameters.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        parameters.SourceId = sysmon_provider_guid;
        parameters.EnableFilterDesc = nullptr;
        parameters.FilterDescCount = 0;

        printf("Enabling Sysmon provider...\n");
        status = EnableTraceEx2(sessionHandle, &sysmon_provider_guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                0, 0, 0, &parameters);
        if (status != ERROR_SUCCESS) {
            printf("EnableTraceEx2() failed with %d\n", status);
        }

        sessionHandle_ = sessionHandle;

cleanup:
        printf("Sysmon Etw Publisher setup done...\n");

#if 0
        if (sessionProperties != nullptr) {
            free(sessionProperties);
        }
#endif

    }

    std::string guidToString(GUID* guid) {
        char guid_string[37];
        snprintf(
                guid_string, sizeof(guid_string),
                "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                guid->Data1, guid->Data2, guid->Data3,
                guid->Data4[0], guid->Data4[1], guid->Data4[2],
                guid->Data4[3], guid->Data4[4], guid->Data4[5],
                guid->Data4[6], guid->Data4[7]);

        return std::string(guid_string);
    }

    std::string taskidToEventType(DWORD taskId) {
        switch (taskId) {
            case  1  : return "ProcessCreate";
            case  2  : return "Filecreationtimechanged" ;
            case  3  : return "Networkconnectiondetected" ;
            case  4  : return "Sysmonservicestatechanged" ;
            case  5  : return "Processterminated" ;
            case  6  : return "Driverloaded" ;
            case  7  : return "Imageloaded" ;
            case  8  : return "CreateRemoteThreaddetected" ;
            case  9  : return "RawAccessReaddetected" ;
            case  10 : return "Processaccessed" ;
            case  11 : return "Filecreated" ;
            case  12 : return "Registryobjectaddedordeleted" ;
            case  13 : return "Registryvalueset" ;
            case  14 : return "Registryobjectrenamed" ;
            case  15 : return "Filestreamcreated" ;
            case  16 : return "Sysmonconfigstatechanged" ;
            case  17 : return "PipeCreated" ;
            case  18 : return "PipeConnected" ;
            case  19 : return "WmiEventFilteractivitydetected" ;
            case  20 : return "WmiEventConsumeractivitydetected" ;
            case  21 : return "WmiEventConsumerToFilteractivitydetected" ;
            case  22 : return "Dnsquery" ;
            case  23 : return "FileDelete" ;
            case  24 : return "Clipboardchanged" ;
            case  25 : return "ProcessTampering" ;
            default: return "";
        }
    }

    bool WINAPI SysmonEtwEventPublisher::processEtwRecord(PEVENT_RECORD pEvent) {
        // This call back is set in user trace created in configure() Once
        // configured receives the event on the session via sysmon provider
        // This is the core function which delivers the event to the
        // appropriate subscriber based on opcode (event type) to either
        // process, image load, registry or dnsquery subscribor. Passing along
        // the event data on fire()

        // Event Header requires no processing
        if (IsEqualGUID(pEvent->EventHeader.ProviderId, EventTraceGuid) &&
                pEvent->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_INFO) {
            return false;
        }

        ULONG buffSize = 0;
        PTRACE_EVENT_INFO info = nullptr;
        auto status = TdhGetEventInformation(pEvent, 0, nullptr, info, &buffSize);

        if (ERROR_INSUFFICIENT_BUFFER == status) {
            info = static_cast<TRACE_EVENT_INFO*>(malloc(buffSize));
            if (info == nullptr) {
                LOG(WARNING) << "Failed to allocate memory for event info";
                return false;
            }

            // Retrieve the event metadata.
            status = TdhGetEventInformation(pEvent, 0, nullptr, info, &buffSize);
        }

        std::vector<wchar_t> formattedData;
        auto pUserData = static_cast<PBYTE>(pEvent->UserData);
        auto pEndOfUserData =
            static_cast<PBYTE>(pEvent->UserData) + pEvent->UserDataLength;

        unsigned long ptrSize =
            (EVENT_HEADER_FLAG_32_BIT_HEADER ==
             (pEvent->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER))
            ? 4 : 8;

        // Parase event record info and fill in the context for event
        USHORT propLen           = 0;
        ULONG  mapSize           = 0;
        ULONG  formattedDataSize = 0;
        USHORT userDataConsumed  = 0;
        PEVENT_MAP_INFO mapInfo = nullptr;
        // Event specific data {event id : value}
        std::map<std::wstring, std::wstring> connDetails;

        EVENT_HEADER eventHdr    = pEvent->EventHeader;
        USHORT taskId            = eventHdr.EventDescriptor.Task;
        std::string providerGuid = guidToString(&eventHdr.ProviderId);

#ifdef SYSMON_PRINT_EVENT
        printf("\n\n*****************EVENT RECORD********************\n");
        printf("providerGuid: %s\n", providerGuid.c_str());
        printf("taskId: %d eventType: %s \n", taskId, taskidToEventType(taskId).c_str());
#endif

        // Iterate over all the property contained in event record and get
        // details about each property
        for (unsigned short i = 0; i < info->TopLevelPropertyCount; i++) {
            propLen = info->EventPropertyInfoArray[i].length;

            status = TdhGetEventMapInformation(
                    pEvent,
                    (wchar_t*)((PBYTE)(info) +
                        info->EventPropertyInfoArray[i].nonStructType.MapNameOffset),
                    mapInfo,
                    &mapSize);

            status = TdhFormatProperty(
                    info,
                    mapInfo,
                    ptrSize,
                    info->EventPropertyInfoArray[i].nonStructType.InType,
                    info->EventPropertyInfoArray[i].nonStructType.OutType,
                    propLen,
                    static_cast<unsigned short>(pEndOfUserData - pUserData),
                    pUserData,
                    &formattedDataSize,
                    formattedData.data(),
                    &userDataConsumed);

            if (ERROR_INSUFFICIENT_BUFFER == status) {
                formattedData.resize(formattedDataSize);
                status = TdhFormatProperty(
                        info,
                        mapInfo,
                        ptrSize,
                        info->EventPropertyInfoArray[i].nonStructType.InType,
                        info->EventPropertyInfoArray[i].nonStructType.OutType,
                        propLen,
                        static_cast<unsigned short>(pEndOfUserData - pUserData),
                        pUserData,
                        &formattedDataSize,
                        formattedData.data(),
                        &userDataConsumed);
            }

            pUserData += userDataConsumed;

            wchar_t* name = (wchar_t*)((PBYTE)(info) + info->EventPropertyInfoArray[i].NameOffset);
            connDetails[name] = std::wstring(formattedData.data());

#ifdef SYSMON_PRINT_EVENT
            printf("%ws: %ws\n", name, connDetails[name].c_str());
#endif
        }

#ifdef SYSMON_PRINT_EVENT
        printf("******************************************\n");
#endif


        // We leave the parsing of the properties up to the subscriber
        auto ec = createEventContext();
        ec->eventData       = connDetails;
        ec->etwProviderGuid = pEvent->EventHeader.ProviderId;
        ec->ProviderGuid    = providerGuid;
        ec->taskId         = taskId;

        ec->pid     = pEvent->EventHeader.ProcessId;
        ec->eventId = pEvent->EventHeader.EventDescriptor.Id;
        ec->level   = pEvent->EventHeader.EventDescriptor.Level;
        ec->channel = pEvent->EventHeader.EventDescriptor.Channel;
        ec->uptime  = pEvent->EventHeader.ProcessorTime;

        FILETIME   ft;
        SYSTEMTIME st;
        SYSTEMTIME stLocal;
        ULONGLONG TimeStamp = 0;
        ULONGLONG Nanoseconds = 0;

        ft.dwLowDateTime = pEvent->EventHeader.TimeStamp.LowPart;
        ft.dwHighDateTime = pEvent->EventHeader.TimeStamp.HighPart;

        FileTimeToSystemTime(&ft, &st);
        SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);

        TimeStamp = pEvent->EventHeader.TimeStamp.QuadPart;
        Nanoseconds = (TimeStamp % 10000000) * 100;
        ec->timestamp = Nanoseconds;

        // We do get taskId from subscriber during subscription (via sc). That
        // will be used to invoke appropriate subscriber during shouldFire().
        EventFactory::getInstance().fire<SysmonEtwEventPublisher>(ec);

        if (info != nullptr) {
            free(info);
        }

        return true;
    }

    Status SysmonEtwEventPublisher::run() {
        // setup the callback function for EVENT_RECORD to processEtwRecord
        printf("Starting SysmonEtwEventPublisher run loop...\n");
        EVENT_TRACE_LOGFILE trace;
        ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
        trace.LogFileName = nullptr;
        trace.LoggerName = OSQUERY_SYSMON_LOGGER_NAME; // Enabling sysmon provider into the trace
        trace.EventCallback = (PEVENT_CALLBACK)processEtwRecord;
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

        hTrace_ = OpenTrace(&trace);
        if (INVALID_PROCESSTRACE_HANDLE == hTrace_) {
            return Status(1,
                    "Failed to open the trace for processing with " +
                    std::to_string(GetLastError()));
        }

        // Process the trace in realtime indefinitely
        auto status = ProcessTrace(&hTrace_, 1, 0, 0);
        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
            return Status(1, "Failed to process trace with " + std::to_string(status));
        }
        return Status::success();
    }


    void SysmonEtwEventPublisher::tearDown() {
        // Cleanup any subscriber specific context here
        if (hTrace_) {
            ::CloseTrace(hTrace_);
            hTrace_ = 0;
        }
        if (sessionHandle_) {
            ::StopTrace(sessionHandle_, OSQUERY_SYSMON_LOGGER_NAME, sessionProperties_);
            sessionHandle_ = 0;
        }

        if(sessionProperties_ != nullptr) {
            free(sessionProperties_);
        }
    }

    bool SysmonEtwEventPublisher::shouldFire(const SysmonEtwSubscriptionContextRef& sc,
            const SysmonEtwEventContextRef& ec) const {
        // Match the task id in event context with subscriber supplied id
        
#if 0
        printf("moose... sc:%d ec:%d\n", sc->taskId, ec->taskId);
#endif
        if (sc->taskId == ec->taskId){
            return true;
        }

        return false;
    }

} // namespace osquery


