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

#include <chrono>
#include <combaseapi.h>


namespace osquery {

    #define OSQUERY_SYSMON_LOGGER_NAME  L"osquery-sysmon-etw-trace"

    REGISTER(SysmonEtwEventPublisher,
            "event_publisher",
            "SysmonEtwEventPublisher");

    const std::string kOsquerySysmonEtwSessionName = "osquery-sysmon-etw-trace";

	static const GUID kOsquerySysmonEtwSessionGuid =
	{ 0x6990501b, 0x4484, 0x4ef0, { 0x87, 0x93, 0x84, 0x15, 0x9b, 0x8d, 0x47, 0x28 } };

    // Sysmon etw trace Microsoft-Windows-Sysmon setup
    // Name: Microsoft-Windows-Sysmon
    // Provider Guid : {5770385F-C22A-43E0-BF4C-06F5698FFBD9}
    // Level: 255
    // KeywordsAll : 0x8000000000000000 (Microsoft-Windows-Sysmon/Operational)
    //
    // Provider guid that we may want to enable on a trace session
    struct __declspec(uuid("{5770385F-C22A-43E0-BF4C-06F5698FFBD9}")) sysmon_guid_holder;
    static const GUID sysmonProviderGuid = __uuidof(sysmon_guid_holder);

    // This is used to generate unique trace guid at runtime
    inline GUID randomGuid() {
        GUID tmpGuid;
        CoCreateGuid(&tmpGuid);
        return tmpGuid;
    }


    void SysmonEtwEventPublisher::stopPrevEtwSession() {
        // Allocate buffer for session properties of the trace
        PEVENT_TRACE_PROPERTIES sessionProperties = nullptr;
        std::unique_ptr<BYTE[]> propertiesBuffer;

        ULONG buffSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(OSQUERY_SYSMON_LOGGER_NAME);
        propertiesBuffer = std::make_unique<BYTE[]>(buffSize);
        ZeroMemory(propertiesBuffer.get(), buffSize);

        sessionProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(propertiesBuffer.get());

        sessionProperties->MaximumFileSize     = 1;
        sessionProperties->Wnode.ClientContext = 1;
        sessionProperties->Wnode.BufferSize    = buffSize;
        sessionProperties->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        sessionProperties->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        sessionProperties->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
        sessionProperties->Wnode.Guid          = kOsquerySysmonEtwSessionGuid;

        auto status = ControlTrace(NULL,
                OSQUERY_SYSMON_LOGGER_NAME,
                sessionProperties,
                EVENT_TRACE_CONTROL_STOP);

        if (status != 0 && status != ERROR_MORE_DATA) {
            LOG(WARNING) << "Failed to stop trace with " << status;
        } else {
            LOG(INFO) << "Stopped the previous trace.";
        }
    }

    void SysmonEtwEventPublisher::configure() {
        // Allocate buffer for session properties of the trace
        PEVENT_TRACE_PROPERTIES sessionProperties = nullptr;
        std::unique_ptr<BYTE[]> propertiesBuffer;

        ULONG buffSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(OSQUERY_SYSMON_LOGGER_NAME);
        propertiesBuffer = std::make_unique<BYTE[]>(buffSize);
        ZeroMemory(propertiesBuffer.get(), buffSize);

        sessionProperties = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(propertiesBuffer.get());

        sessionProperties->MaximumFileSize     = 1;
        sessionProperties->Wnode.ClientContext = 1;
        sessionProperties->Wnode.BufferSize    = buffSize;
        sessionProperties->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        sessionProperties->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        sessionProperties->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);
        sessionProperties->Wnode.Guid          = kOsquerySysmonEtwSessionGuid;


        TRACEHANDLE sessionHandle = 0;
        auto status = StartTrace(&sessionHandle, OSQUERY_SYSMON_LOGGER_NAME, sessionProperties);

        // If the trace already exists, stop it and restart.
        if (status == ERROR_ALREADY_EXISTS) {
            printf("Stopping trace sesson before starting a new one...\n");
            // May be a better cleanup functio, coz this will interrupt the main thread
            stopPrevEtwSession();

            status = StartTrace((PTRACEHANDLE)&sessionHandle,
                    OSQUERY_SYSMON_LOGGER_NAME,
                    sessionProperties);
        }

        if (sessionHandle == 0) {
            LOG(WARNING) << "Failed to start trace for provider with " << status;
            goto cleanup;
        }

        sessionHandle_ = sessionHandle;

        // Enable sysmon provider for the trace session created previously.
        // Such that we can receive the events on the enabled provider emits
        // based on the trace configuration.
        ENABLE_TRACE_PARAMETERS parameters;
        ZeroMemory(&parameters, sizeof(parameters));

        parameters.ControlFlags     = 0;
        parameters.Version          = ENABLE_TRACE_PARAMETERS_VERSION_2;
        parameters.SourceId         = sysmonProviderGuid;
        parameters.EnableFilterDesc = nullptr;
        parameters.FilterDescCount  = 0;

        printf("Enabling Sysmon provider...\n");
        status = EnableTraceEx2(sessionHandle, &sysmonProviderGuid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                0, 0, 0, &parameters);
        if (status != ERROR_SUCCESS) {
            printf("EnableTraceEx2() failed with %d\n", status);
        }


cleanup:
        printf("Sysmon Etw Publisher setup done...\n");
    }

    std::string guidToString(GUID* guid) {
        char guidStr[37];
        snprintf(
                guidStr, sizeof(guidStr),
                "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                guid->Data1, guid->Data2, guid->Data3,
                guid->Data4[0], guid->Data4[1], guid->Data4[2],
                guid->Data4[3], guid->Data4[4], guid->Data4[5],
                guid->Data4[6], guid->Data4[7]);

        return std::string(guidStr);
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



#if 0
        // Let's check if publisher is going down...if yes let's just end this
        auto pubref = EventFactory::getEventPublisher(std::string("SysmonEtwEventPublisher"));
        if (pubref->isEnding()) {
            printf("Event publisher ending...bail out.\n");
            return false;
        }
#endif

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
        ec->taskId          = taskId;

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

        // This is one way to close and return from blocking ProcessTrace
        if (ERROR_SUCCESS != status || NULL == pUserData)
        {
            printf("processEtwRecord returned %d\n", status);
            return false;
        }

        return true;
    }

    // ProcessTrace() is a blocking api, creating this thread stub helps return
    // in the event publisher run loop
    DWORD SysmonEtwEventPublisher::sysmonProcessTraceThread(LPVOID param) {
        // Grab sysmon trace handle opened in configure and run.
        TRACEHANDLE htraceSysmon = *(TRACEHANDLE*)param;

        auto status = ProcessTrace(&htraceSysmon, 1, 0, 0);
        if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
            return status;
        }

        return ERROR_SUCCESS;
    }

    Status SysmonEtwEventPublisher::run() {
        // Setup the callback function for EVENT_RECORD to processEtwRecord
        printf("Starting SysmonEtwEventPublisher run loop...\n");
        EVENT_TRACE_LOGFILE trace;
        ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));

        trace.LogFileName      = nullptr;
        trace.LoggerName       = OSQUERY_SYSMON_LOGGER_NAME;
        trace.EventCallback    = (PEVENT_CALLBACK)processEtwRecord;
        trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;

        hTrace_ = OpenTrace(&trace);
        if (INVALID_PROCESSTRACE_HANDLE == hTrace_) {
            return Status(1,
                    "Failed to open the trace for processing with " +
                    std::to_string(GetLastError()));
        }

        DWORD tidTracer;
        printf("Creating Process tracer thread.\n");
        HANDLE hthreadTracer = CreateThread(0, 0, sysmonProcessTraceThread, (LPVOID)&hTrace_, 0, &tidTracer);
        CloseHandle(hthreadTracer);

        while(!isEnding()) {
            // TODO: Batch event lists here and thus put lesser pressure on
            // rocskdb and use addBatch() at subscriber side
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        return Status::success();
    }


    void SysmonEtwEventPublisher::stop() {
        stopPrevEtwSession();
    }

    void SysmonEtwEventPublisher::tearDown() {
        // Cleanup any subscriber specific context here

        if (hTrace_) {
            ::CloseTrace(hTrace_);
            hTrace_ = 0;
        }

        printf("SysmonEtwPublisher tearDown() isEnding: %s\n", isEnding() ? "true" : "false");
        if (isEnding()) {
            stopPrevEtwSession();
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


