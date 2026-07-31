"""Declarative tool profiles and MCP side-effect metadata.

This module is deliberately independent from :mod:`x64dbg`.  The server can
load all of its built-in and ``ext_tools`` functions first, then pass the final
registry to :func:`build_tool_catalog` or :func:`apply_tool_metadata`.

Profiles are discovery aids, not an authorization boundary.  In particular,
``full`` remains the default so adding this module cannot silently hide an
existing MCP tool from current clients.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence


SCHEMA_VERSION = 2
RESULT_CONTRACT = "envelope-v1"
LEGACY_RESULT_SHIM = {
    "environmentVariable": "X64DBG_MCP_LEGACY_RESULTS",
    "sunset": "2026-12-31",
}
DEFAULT_PROFILE = "full"
RECOMMENDED_PROFILE = "compact"
PROFILE_NAMES = ("compact", "inspect", "standard", "automation", "full")

RISK_LEVELS = (
    "read",
    "reversible",
    "consequential",
    "privileged",
    "unbounded",
)

SIDE_EFFECT_KINDS = frozenset(
    {
        "mcp.state.write",
        "debugger.database.write",
        "debugger.configuration.write",
        "debugger.breakpoint.write",
        "debuggee.execution",
        "debuggee.memory.write",
        "debuggee.thread.control",
        "debuggee.input",
        "debuggee.module.inject",
        "host.process.control",
        "host.user-input",
        "host.filesystem.write",
        "host.configuration.write",
        "kernel.driver.control",
        "unbounded.command",
    }
)

TOUCH_KINDS = frozenset(
    {
        "mcp",
        "bridge",
        "debugger",
        "debuggee",
        "filesystem",
        "host-process",
        "windows-ui",
        "kernel",
    }
)

REQUIREMENT_KINDS = frozenset({"bridge", "debug-session", "elevation"})


class ToolProfileError(ValueError):
    """Raised when a registry or profile has no complete, safe policy."""


def _names(value: str) -> frozenset[str]:
    return frozenset(value.split())


# Deliberately small workflow facade for model-driven reversing.  The complete
# registry remains available through ``full`` and no tool is unregistered.
COMPACT_TOOLS = _names(
    """
    EnsureReady BridgeHello InitDebuggee AttachToProcess
    DebugRun DebugPause DebugStop DebugStepIn DebugStepOver DebugStepOut
    WaitForPause WaitForExit GetDebugState GetSessionBinding
    GetModuleList GetThreadList GetCallStack GetRegisterDump
    ReadMemory MemoryWrite DisasmRange EvalBatch GetImports GetExports
    SearchStrings SetBreakpointWithCapture DebugDeleteBreakpoint
    CaptureStopContextStructured StartApiTrace RunApiTrace GetApiTraceLog
    StopApiTrace DumpPeFromMemory DumpModule ValidateDump FindOEP
    RecoverComparisonSecret InspectManagedAssembly CaptureManagedRuntimeState
    ExportRuntimeEvidence
    """
)


# One primary category per shipped tool.  The explicit inventory is
# intentional: a new tool must not become read-only or standard-visible merely
# because its name happens to match a permissive prefix.
CATEGORY_TOOLS: Mapping[str, frozenset[str]] = {
    "session": _names(
        """
        BindSessionTarget BridgeHello ClearSessionBinding EnsureReady
        AcquireMutationLease ReleaseMutationLease RenewMutationLease
        ClearExceptionHistory ClearExceptionPolicy GetDebugState GetDebugStateLean
        GetExceptionHistory GetExceptionPolicy GetSessionBinding IsDebugActive IsDebugging
        SetExceptionFilter SetExceptionPolicy GetChildBrokerState GetSelectedDebugSession
        ListDebugSessions SelectDebugSession
        """
    ),
    "diagnostics": _names(
        """
        BenchmarkBridge ExportCapabilityMap GetDebuggerPluginStatus GetRecentLog
        RunBridgeSelfCheck
        """
    ),
    "inspection": _names(
        """
        EnumHandles EnumTcpConnections EvalBatch GetInputHistory GetInteractionHistory
        GetModuleList GetPatchAt GetPatchList MiscParseExpression
        MiscRemoteGetProcAddress ReadFrame
        """
    ),
    "code-analysis": _names(
        """
        AnalyzeExecutablePacking AssemblerAssemble DisasmFunction
        DisasmGetInstructionRange DisasmRange GetBranchDestination GetExports
        GetFunctionArgs GetFunctionInfo GetImports ScanMemoryStrings SearchStrings
        XrefCount XrefGet InspectManagedAssembly GetManagedRuntimeState
        ResolveManagedToken CaptureManagedRuntimeState ResolveManagedJitMethod
        """
    ),
    "memory": _names(
        """
        AssemblerAssembleMem DecodeStructuredValue FlagGet FlagSet GetMemoryMap
        GetMemorySnapshot GetRegisterDump MemoryBase MemoryGetProtect MemoryIsValidPtr
        MemoryRead MemoryRemoteAlloc MemoryRemoteFree MemoryWrite PatternFindMem
        ReadLocalBuffer ReadMemory ReadMemoryBatch RegisterGet RegisterSet SetPageRights
        StackPeek StackPop StackPush StringGetAt
        """
    ),
    "annotations": _names(
        """
        BookmarkDelete BookmarkGet BookmarkList BookmarkSet CommentDelete CommentGet
        CommentList CommentSet ExportAnalysisEvidence FunctionAdd FunctionDelete
        FunctionList ImportAnalysisEvidence LabelDelete LabelGet LabelList LabelSet
        ValidateAnalysisEvidence ResolveModuleRva ExportRuntimeEvidence
        ImportStaticAnnotations SyncBreakpoints ExportManagedEvidence
        ExportManagedRuntimeEvidence ExportManagedAssemblyMetadata
        """
    ),
    "execution": _names(
        """
        AdvancePastStartupPause ContinueException DebugPause DebugRun DebugRunBlocking
        DebugStepIn DebugStepOut DebugStepOver DebugStop ReplayToAddress RunToUserCode
        RunUntil RunUntilModuleLoad RunUntilOEP StepInWithDisasm StepWithSnapshot
        WaitForExit WaitForModuleLoad WaitForPause WaitForUserCode WatchMemoryChanges
        """
    ),
    "breakpoints": _names(
        """
        BatchBreakpointsCapture CaptureSymbolicBreakpoint DebugDeleteBreakpoint
        DebugSetBreakpoint DeleteHardwareBreakpoint DeleteMemoryBreakpoint
        GetBreakpointCaptureHistory GetBreakpointList SetBreakpointWithCapture
        SetConditionalBreakpoint SetHardwareBreakpoint SetMemoryRangeBreakpoint
        SetMemoryWatchpointWithCapture WaitForBreakpoint WaitForBreakpointCapture
        WaitForBreakpointCaptureStructured WaitForBreakpointDetailed
        AcquireBreakpointLease RenewBreakpointLease ReleaseBreakpointLease
        ListBreakpointLeases SetManagedMethodBreakpoint
        """
    ),
    "tracing": _names(
        """
        CaptureExecuteAfterWrite ClearNativeApiTraceEvidence FinalizeNativeApiTraceEvidence
        ClearNativeTrace GetApiTraceLog
        GetNativeApiTraceEvidence GetBasicBlockCoverage ExportCoverageArtifact
        MergeCoverageArtifacts DiffCoverageArtifacts
        GetHeapState GetNativeTrace
        GetTraceHistory GetTraceRecord ListApiTraces RecoverComparisonSecret
        GetManagedExceptionHistory RunApiTrace RunHeapTrace
        RunNativeTrace RunTraceRecord StartApiTrace StartHeapTrace StartNativeTrace
        StartRunTraceToFile StartTraceRecord StopApiTrace StopNativeTrace StopRunTrace
        StopTraceRecord SummarizeTraceHistory TraceApiCalls TraceInstructionTape
        TraceIntoConditional TraceOverConditional WaitNativeTrace
        """
    ),
    "snapshots": _names(
        """
        CaptureContext CaptureMemorySnapshot CaptureStopContextStructured Checkpoint
        ClearRuntimeHistory CompareMemorySnapshots DeleteStateSnapshot GetStateSnapshot
        ListStateSnapshots RestoreState Rewind SaveState
        """
    ),
    "process": _names(
        """
        AttachToProcess CloseLaunchResources CloseLaunchStdin EnsureDebugger
        FollowChildProcess GetLaunchState GetProcessDebugStatus InitDebuggee
        LaunchAndOpenDebuggee LaunchFileUnderDebugger ListChildProcesses
        LoadLibraryInDebuggee ReadLaunchStream RemoveProcessDebug RestartDebugger
        WaitForChildProcess WriteLaunchStdin
        """
    ),
    "threads": _names(
        """
        GetCallStack GetTebAddress GetThreadList ResumeAllThreads ResumeThread
        SetThreadPriority SuspendAllThreads SuspendThread SwitchThread
        """
    ),
    "symbols": _names("LoadSymbolsForModule QuerySymbols"),
    "dumping": _names(
        """
        DumpLoadedModule DumpMemoryMapManifest DumpModule DumpModuleRaw DumpPeFromMemory
        ExportPatchedFile FindIATCandidates FindOEP FixDumpImports GetMiniDumpProfiles
        DumpOnEvent InspectProcessPayload InspectRuntimeIAT ScanMemoryForPEImages
        RecoverRuntimeImports ValidateDump ValidateIAT
        ReconstructImports SaveMemoryRegionToFile VerifyMiniDump VerifyPEDump
        WriteMiniDump
        """
    ),
    "ui": _names(
        """
        AnalyzeDebuggeeGui AnalyzeDebuggeeInput AnalyzeDebuggeeInteraction
        AnalyzeDebuggeeUiAutomation AutoRespondToDebuggeeConsole AutoRespondToDebuggeeGui
        CaptureDebuggeeWindow ClickActiveWindow ClickControl ClickDebuggeeWindow
        CompareWindowCaptures DragDebuggeeWindow FocusDebuggeeWindow
        GetDebuggeeUiAutomation GetDebuggeeWindows GetForegroundWindowInfo
        GetWindowCapture GetWindowCaptureHistory InvokeUiAutomationElement
        ReadControlText ReadDebuggeeConsole ScrollActiveWindow ScrollDebuggeeWindow
        SendForegroundKeys SendTextToActiveWindow SendTextToDebuggeeConsole
        SendTextToDebuggeeWindow SetControlText SetUiAutomationValue
        SubmitDebuggeeGuiForm SubmitDebuggeeUiAutomation WaitForDebuggeeInputIdle
        WaitForDebuggeeWindow WaitForDebuggeeWindowReady WaitForForegroundChange
        WaitForGuiChange WaitForWindowVisualChange
        """
    ),
    "anti-debug": _names(
        """
        AnalyzeAntiDebugSurface ConfigureHideMainPlugin EnsureHideMainForDebuggee
        EnsureScyllaHideForDebuggee GetHideMainStatus GetScyllaHideStatus
        HideDebuggeeWithHideMain ManageHideMainDriver SetScyllaHideProfile
        UnhideDebuggeeWithHideMain
        """
    ),
    "raw": _names("ExecCommand"),
}


def _effect_map() -> dict[str, frozenset[str]]:
    """Return explicit effect groups used by the policy builder."""

    return {
        "mcp.state.write": _names(
            """
            BindSessionTarget CaptureDebuggeeWindow CaptureMemorySnapshot Checkpoint
            AcquireMutationLease ReleaseMutationLease RenewMutationLease
            ClearExceptionHistory ClearExceptionPolicy ClearNativeApiTraceEvidence
            FinalizeNativeApiTraceEvidence ClearNativeTrace CloseLaunchResources
            ClearRuntimeHistory ClearSessionBinding DeleteStateSnapshot SaveState
            SetExceptionFilter SetExceptionPolicy StartApiTrace StartHeapTrace
            StartNativeTrace StartTraceRecord StopApiTrace StopNativeTrace StopTraceRecord
            """
        ),
        "debugger.database.write": _names(
            """
            BookmarkDelete BookmarkSet CommentDelete CommentSet FunctionAdd
            FunctionDelete ImportAnalysisEvidence ImportStaticAnnotations
            LabelDelete LabelSet
            """
        ),
        "debugger.configuration.write": _names(
            """
            ClearExceptionPolicy LoadSymbolsForModule SetExceptionFilter
            SetExceptionPolicy StartRunTraceToFile StopRunTrace
            """
        ),
        "debugger.breakpoint.write": _names(
            """
            BatchBreakpointsCapture CaptureSymbolicBreakpoint DebugDeleteBreakpoint
            DebugSetBreakpoint DeleteHardwareBreakpoint DeleteMemoryBreakpoint DumpModule
            FindOEP RunUntil RunUntilOEP SetBreakpointWithCapture
            SetConditionalBreakpoint SetHardwareBreakpoint SetMemoryRangeBreakpoint
            SetMemoryWatchpointWithCapture CaptureExecuteAfterWrite SetManagedMethodBreakpoint
            AcquireBreakpointLease
            RenewBreakpointLease ReleaseBreakpointLease
            StartApiTrace StartHeapTrace StartTraceRecord
            StopApiTrace StopTraceRecord TraceApiCalls
            """
        ),
        "debuggee.execution": _names(
            """
            AdvancePastStartupPause BatchBreakpointsCapture CaptureExecuteAfterWrite
            CaptureManagedRuntimeState CaptureSymbolicBreakpoint ExportManagedRuntimeEvidence
            ExportManagedAssemblyMetadata ResolveManagedJitMethod SetManagedMethodBreakpoint
            ContinueException DebugPause DebugRun DebugRunBlocking DebugStepIn DebugStepOut
            DebugStepOver DebugStop DumpModule DumpOnEvent FindOEP FollowChildProcess ReplayToAddress
            RunApiTrace RunHeapTrace RunNativeTrace RunToUserCode RunTraceRecord RunUntil
            RunUntilModuleLoad RunUntilOEP SetBreakpointWithCapture
            SetMemoryWatchpointWithCapture StepInWithDisasm StepWithSnapshot TraceApiCalls
            TraceInstructionTape TraceIntoConditional TraceOverConditional
            WaitForBreakpointCapture WaitForBreakpointCaptureStructured WaitForModuleLoad
            WaitForUserCode WatchMemoryChanges WriteMiniDump
            """
        ),
        "debuggee.memory.write": _names(
            """
            AssemblerAssembleMem FlagSet MemoryRemoteAlloc MemoryRemoteFree MemoryWrite
            RegisterSet ReplayToAddress RestoreState Rewind SetPageRights StackPop StackPush
            """
        ),
        "debuggee.thread.control": _names(
            """
            ResumeAllThreads ResumeThread SetThreadPriority SuspendAllThreads SuspendThread
            SwitchThread
            """
        ),
        "debuggee.input": _names(
            """
            AutoRespondToDebuggeeConsole AutoRespondToDebuggeeGui CaptureDebuggeeWindow
            ClickControl ClickDebuggeeWindow CloseLaunchStdin DragDebuggeeWindow FocusDebuggeeWindow
            InvokeUiAutomationElement ScrollDebuggeeWindow SendTextToDebuggeeConsole
            SendTextToDebuggeeWindow SetControlText SetUiAutomationValue
            SubmitDebuggeeGuiForm SubmitDebuggeeUiAutomation WriteLaunchStdin
            """
        ),
        "debuggee.module.inject": _names(
            """
            EnsureScyllaHideForDebuggee LaunchAndOpenDebuggee
            LaunchFileUnderDebugger LoadLibraryInDebuggee
            """
        ),
        "host.process.control": _names(
            """
            AttachToProcess DebugStop EnsureDebugger FollowChildProcess InitDebuggee
            LaunchAndOpenDebuggee LaunchFileUnderDebugger RemoveProcessDebug RestartDebugger
            """
        ),
        "host.user-input": _names(
            "ClickActiveWindow ScrollActiveWindow SendForegroundKeys SendTextToActiveWindow"
        ),
        "host.filesystem.write": _names(
            """
            CaptureDebuggeeWindow ConfigureHideMainPlugin DumpLoadedModule DumpModule
            DumpModuleRaw DumpOnEvent DumpPeFromMemory ExportAnalysisEvidence ExportCapabilityMap ExportPatchedFile
            ExportRuntimeEvidence ExportManagedEvidence ExportManagedRuntimeEvidence
            ExportManagedAssemblyMetadata
            FixDumpImports RecoverRuntimeImports
            ReconstructImports SaveMemoryRegionToFile SetScyllaHideProfile
            StartRunTraceToFile TraceIntoConditional TraceOverConditional WriteMiniDump
            """
        ),
        "host.configuration.write": _names(
            """
            AttachToProcess ConfigureHideMainPlugin EnsureHideMainForDebuggee
            LaunchAndOpenDebuggee LaunchFileUnderDebugger ManageHideMainDriver
            SetScyllaHideProfile
            """
        ),
        "kernel.driver.control": _names(
            """
            AttachToProcess EnsureHideMainForDebuggee HideDebuggeeWithHideMain
            LaunchAndOpenDebuggee LaunchFileUnderDebugger ManageHideMainDriver
            UnhideDebuggeeWithHideMain
            """
        ),
        "unbounded.command": _names("ExecCommand"),
    }


EFFECT_TOOLS = _effect_map()


CONDITIONAL_EFFECTS: Mapping[str, tuple[Mapping[str, Any], ...]] = {
    "ExportRuntimeEvidence": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "output_path", "operator": "nonempty"},
        },
    ),
    "ExportManagedEvidence": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "output_path", "operator": "nonempty"},
        },
    ),
    "ExportManagedRuntimeEvidence": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "output_path", "operator": "nonempty"},
        },
    ),
    "ExportManagedAssemblyMetadata": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "output_path", "operator": "nonempty"},
        },
    ),
    "CaptureManagedRuntimeState": (
        {
            "kind": "debuggee.execution",
            "when": {"parameter": "pause_if_running", "operator": "equals", "value": True},
        },
        {
            "kind": "debuggee.execution",
            "when": {"parameter": "resume_after", "operator": "equals", "value": True},
        },
    ),
    "ImportStaticAnnotations": (
        {
            "kind": "debugger.database.write",
            "when": {"parameter": "dry_run", "operator": "equals", "value": False},
        },
    ),
    "SyncBreakpoints": (
        {
            "kind": "debugger.breakpoint.write",
            "when": {"parameter": "apply", "operator": "equals", "value": True},
        },
    ),
    "AttachToProcess": (
        {
            "kind": "kernel.driver.control",
            "when": {"parameter": "use_hidemain", "operator": "not_equals", "value": "off"},
        },
        {
            "kind": "host.configuration.write",
            "when": {
                "parameter": "hidemain_allow_system_changes",
                "operator": "equals",
                "value": True,
            },
        },
    ),
    "CaptureDebuggeeWindow": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "save_path", "operator": "nonempty"},
        },
    ),
    "CaptureExecuteAfterWrite": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "evidence_path", "operator": "nonempty"},
        },
    ),
    "RecoverComparisonSecret": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "evidence_path", "operator": "nonempty"},
        },
    ),
    "ConfigureHideMainPlugin": (
        {
            "kind": "host.configuration.write",
            "when": {"parameter": "action", "operator": "not_equals", "value": "status"},
        },
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "action", "operator": "not_equals", "value": "status"},
        },
    ),
    "ExportAnalysisEvidence": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "output_path", "operator": "nonempty"},
        },
    ),
    "ExportCapabilityMap": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "output_path", "operator": "nonempty"},
        },
    ),
    "DumpMemoryMapManifest": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "output_path", "operator": "nonempty"},
        },
    ),
    "ValidateDump": (
        {
            "kind": "host.process.control",
            "when": {"parameter": "run_isolated", "operator": "equals", "value": True},
        },
    ),
    "ImportAnalysisEvidence": (
        {
            "kind": "debugger.database.write",
            "when": {"parameter": "dry_run", "operator": "equals", "value": False},
        },
    ),
    "LaunchAndOpenDebuggee": (
        {
            "kind": "debuggee.module.inject",
            "when": {"parameter": "use_scyllahide", "operator": "not_equals", "value": "off"},
        },
        {
            "kind": "kernel.driver.control",
            "when": {"parameter": "use_hidemain", "operator": "not_equals", "value": "off"},
        },
        {
            "kind": "host.configuration.write",
            "when": {
                "parameter": "hidemain_allow_system_changes",
                "operator": "equals",
                "value": True,
            },
        },
    ),
    "LaunchFileUnderDebugger": (
        {
            "kind": "debuggee.module.inject",
            "when": {"parameter": "use_scyllahide", "operator": "not_equals", "value": "off"},
        },
        {
            "kind": "kernel.driver.control",
            "when": {"parameter": "use_hidemain", "operator": "not_equals", "value": "off"},
        },
        {
            "kind": "host.configuration.write",
            "when": {
                "parameter": "hidemain_allow_system_changes",
                "operator": "equals",
                "value": True,
            },
        },
    ),
    "ManageHideMainDriver": (
        {
            "kind": "kernel.driver.control",
            "when": {"parameter": "action", "operator": "not_equals", "value": "status"},
        },
        {
            "kind": "host.configuration.write",
            "when": {"parameter": "action", "operator": "not_equals", "value": "status"},
        },
    ),
    "TraceIntoConditional": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "log_file", "operator": "nonempty"},
        },
    ),
    "TraceOverConditional": (
        {
            "kind": "host.filesystem.write",
            "when": {"parameter": "log_file", "operator": "nonempty"},
        },
    ),
    "WaitForModuleLoad": (
        {
            "kind": "debuggee.execution",
            "when": {"parameter": "auto_run", "operator": "equals", "value": True},
        },
    ),
    "WriteMiniDump": (
        {
            "kind": "debuggee.execution",
            "when": {"parameter": "pause_if_running", "operator": "equals", "value": True},
        },
        {
            "kind": "debuggee.execution",
            "when": {"parameter": "resume_after", "operator": "equals", "value": True},
        },
    ),
}


GLOBAL_INPUT_TOOLS = EFFECT_TOOLS["host.user-input"]

EXPERT_ONLY_TOOLS = _names(
    """
    AssemblerAssembleMem ConfigureHideMainPlugin EnsureHideMainForDebuggee
    EnsureScyllaHideForDebuggee ExecCommand HideDebuggeeWithHideMain
    LoadLibraryInDebuggee ManageHideMainDriver MemoryRemoteAlloc MemoryRemoteFree
    RemoveProcessDebug RestartDebugger SetPageRights SetScyllaHideProfile StackPop
    StackPush UnhideDebuggeeWithHideMain
    """
)

# These high-level entry points deliberately remain discoverable in the normal
# profiles even though optional arguments can opt into privileged anti-debug
# helpers.  Their conditional metadata makes that escalation visible.
PRIVILEGED_PROFILE_EXCEPTIONS = _names(
    "AttachToProcess LaunchAndOpenDebuggee LaunchFileUnderDebugger"
)

IDEMPOTENT_MUTATIONS = _names(
    """
    BindSessionTarget BookmarkDelete BookmarkSet ClearExceptionHistory
    ReleaseMutationLease
    ClearExceptionPolicy ClearNativeApiTraceEvidence FinalizeNativeApiTraceEvidence
    ClearNativeTrace
    ClearRuntimeHistory ClearSessionBinding
    CloseLaunchResources CloseLaunchStdin
    CommentDelete CommentSet DebugDeleteBreakpoint DebugPause DebugSetBreakpoint DebugStop
    DeleteHardwareBreakpoint DeleteMemoryBreakpoint DeleteStateSnapshot FlagSet FunctionAdd
    FunctionDelete LabelDelete LabelSet MemoryWrite RegisterSet SetConditionalBreakpoint
    SetControlText SetExceptionFilter SetHardwareBreakpoint SetManagedMethodBreakpoint
    SetMemoryRangeBreakpoint
    SetPageRights SetScyllaHideProfile SetThreadPriority SetUiAutomationValue StopApiTrace
    StopNativeTrace StopRunTrace StopTraceRecord SwitchThread UnhideDebuggeeWithHideMain
    """
)

DESTRUCTIVE_NAMES = _names(
    """
    BookmarkDelete ClearExceptionHistory ClearExceptionPolicy
    ClearNativeApiTraceEvidence FinalizeNativeApiTraceEvidence ClearNativeTrace
    ClearRuntimeHistory
    CommentDelete DebugDeleteBreakpoint DebugStop
    DeleteHardwareBreakpoint DeleteMemoryBreakpoint DeleteStateSnapshot FunctionDelete
    LabelDelete RemoveProcessDebug StopApiTrace StopTraceRecord
    """
)

OFFLINE_OR_SESSION_OPTIONAL = _names(
    """
    AnalyzeAntiDebugSurface AnalyzeExecutablePacking AttachToProcess BridgeHello
    CloseLaunchResources CloseLaunchStdin ConfigureHideMainPlugin EnsureDebugger
    EnsureReady ExportCapabilityMap GetLaunchState ReadLaunchStream WriteLaunchStdin
    GetDebuggerPluginStatus GetHideMainStatus GetMiniDumpProfiles GetRecentLog
    GetScyllaHideStatus InitDebuggee LaunchAndOpenDebuggee LaunchFileUnderDebugger
    ManageHideMainDriver RunBridgeSelfCheck SetScyllaHideProfile
    ValidateAnalysisEvidence VerifyMiniDump VerifyPEDump
    """
)

NO_BRIDGE_REQUIRED = _names(
    """
    AnalyzeAntiDebugSurface AnalyzeExecutablePacking ConfigureHideMainPlugin
    EnsureDebugger ExportCapabilityMap GetDebuggerPluginStatus GetHideMainStatus
    GetMiniDumpProfiles GetScyllaHideStatus ManageHideMainDriver RunBridgeSelfCheck
    SetScyllaHideProfile ValidateAnalysisEvidence VerifyMiniDump VerifyPEDump
    """
)

ELEVATION_REQUIRED = _names("ManageHideMainDriver")


CATEGORY_TOUCHES: Mapping[str, frozenset[str]] = {
    "session": frozenset({"bridge", "debugger"}),
    "diagnostics": frozenset({"bridge", "filesystem"}),
    "inspection": frozenset({"bridge", "debuggee"}),
    "code-analysis": frozenset({"bridge", "debuggee", "filesystem"}),
    "memory": frozenset({"bridge", "debuggee"}),
    "annotations": frozenset({"bridge", "debugger", "filesystem"}),
    "execution": frozenset({"bridge", "debuggee"}),
    "breakpoints": frozenset({"bridge", "debugger", "debuggee"}),
    "tracing": frozenset({"bridge", "debugger", "debuggee", "filesystem"}),
    "snapshots": frozenset({"mcp", "bridge", "debuggee"}),
    "process": frozenset({"bridge", "debuggee", "host-process"}),
    "threads": frozenset({"bridge", "debuggee"}),
    "symbols": frozenset({"bridge", "debugger", "filesystem"}),
    "dumping": frozenset({"bridge", "debuggee", "filesystem"}),
    "ui": frozenset({"bridge", "debuggee", "windows-ui"}),
    "anti-debug": frozenset({"debuggee", "filesystem", "kernel"}),
    "raw": frozenset({"bridge", "debugger", "debuggee"}),
}


PROFILE_DESCRIPTIONS: Mapping[str, str] = {
    "compact": "Forty primary workflow tools for model-driven dynamic reverse engineering.",
    "inspect": "Read-only inspection and validation tools.",
    "standard": "Recommended dynamic reverse-engineering surface without global input, injection, kernel or raw-command tools.",
    "automation": "Standard tools plus debuggee-scoped GUI and console automation.",
    "full": "All registered tools; backward-compatible discovery surface.",
}


@dataclass(frozen=True)
class ToolPolicy:
    name: str
    category: str
    tags: tuple[str, ...]
    profiles: tuple[str, ...]
    risk: str
    touches: tuple[str, ...]
    side_effects: tuple[str, ...]
    conditional_side_effects: tuple[Mapping[str, Any], ...]
    requires: tuple[str, ...]
    read_only: bool
    destructive: bool
    idempotent: bool
    open_world: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "resultContract": RESULT_CONTRACT,
            "legacyResultShim": dict(LEGACY_RESULT_SHIM),
            "category": self.category,
            "tags": list(self.tags),
            "profiles": list(self.profiles),
            "risk": self.risk,
            "touches": list(self.touches),
            "sideEffects": list(self.side_effects),
            "conditionalSideEffects": [dict(item) for item in self.conditional_side_effects],
            "requires": list(self.requires),
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.open_world,
            },
        }


def known_tool_names() -> frozenset[str]:
    """Return the complete tool inventory covered by this policy."""

    result: set[str] = set()
    duplicates: set[str] = set()
    for names in CATEGORY_TOOLS.values():
        duplicates.update(result.intersection(names))
        result.update(names)
    if duplicates:
        raise ToolProfileError(
            "Tools assigned to multiple primary categories: "
            + ", ".join(sorted(duplicates))
        )
    return frozenset(result)


def _registry_names(registry: Mapping[str, Any] | Iterable[str]) -> frozenset[str]:
    if isinstance(registry, Mapping):
        values = registry.keys()
    else:
        values = registry
    names = frozenset(str(name) for name in values)
    if "" in names:
        raise ToolProfileError("Tool names must be non-empty strings")
    return names


def _category_for(name: str) -> str:
    matches = [category for category, names in CATEGORY_TOOLS.items() if name in names]
    if len(matches) != 1:
        if not matches:
            raise ToolProfileError(f"No profile policy for registered tool: {name}")
        raise ToolProfileError(
            f"Tool {name} has multiple primary categories: {', '.join(matches)}"
        )
    return matches[0]


def _effects_for(name: str) -> tuple[str, ...]:
    return tuple(
        sorted(effect for effect, names in EFFECT_TOOLS.items() if name in names)
    )


def _risk_for(effects: Sequence[str], name: str) -> str:
    effect_set = set(effects)
    if "unbounded.command" in effect_set:
        return "unbounded"
    if effect_set.intersection(
        {
            "debuggee.module.inject",
            "host.configuration.write",
            "kernel.driver.control",
        }
    ) or name == "RemoveProcessDebug":
        return "privileged"
    if effect_set.intersection(
        {
            "debuggee.execution",
            "debuggee.memory.write",
            "debuggee.thread.control",
            "debuggee.input",
            "host.process.control",
            "host.user-input",
            "host.filesystem.write",
        }
    ):
        return "consequential"
    if effect_set:
        return "reversible"
    return "read"


def _profiles_for(
    name: str,
    category: str,
    risk: str,
    effects: Sequence[str],
) -> tuple[str, ...]:
    profiles: list[str] = []
    if name in COMPACT_TOOLS:
        profiles.append("compact")
    if not effects:
        profiles.append("inspect")

    standard_visible = (
        (risk not in {"privileged", "unbounded"} or name in PRIVILEGED_PROFILE_EXCEPTIONS)
        and name not in EXPERT_ONLY_TOOLS
        and name not in GLOBAL_INPUT_TOOLS
        and "debuggee.input" not in effects
    )
    if standard_visible:
        profiles.append("standard")

    automation_visible = (
        (risk not in {"privileged", "unbounded"} or name in PRIVILEGED_PROFILE_EXCEPTIONS)
        and name not in EXPERT_ONLY_TOOLS
        and name not in GLOBAL_INPUT_TOOLS
    )
    if automation_visible:
        profiles.append("automation")

    profiles.append("full")
    return tuple(profile for profile in PROFILE_NAMES if profile in profiles)


def _tags_for(
    name: str,
    category: str,
    effects: Sequence[str],
    conditional: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    tags: set[str] = set()
    if name in EXPERT_ONLY_TOOLS:
        tags.add("expert")
    else:
        tags.add("core")
    if name in GLOBAL_INPUT_TOOLS:
        tags.add("global-input")
    if conditional:
        tags.add("conditional-effects")
    if "host.filesystem.write" in effects:
        tags.add("filesystem-write")
    if "kernel.driver.control" in effects:
        tags.update({"kernel", "elevation-sensitive"})
    if "unbounded.command" in effects:
        tags.add("unbounded")
    if category == "ui" and "debuggee.input" not in effects and name not in GLOBAL_INPUT_TOOLS:
        tags.add("ui-inspection")
    return tuple(sorted(tags))


def _requirements_for(name: str) -> tuple[str, ...]:
    requirements: set[str] = set()
    if name not in NO_BRIDGE_REQUIRED:
        requirements.add("bridge")
    if name not in OFFLINE_OR_SESSION_OPTIONAL:
        requirements.add("debug-session")
    if name in ELEVATION_REQUIRED:
        requirements.add("elevation")
    return tuple(sorted(requirements))


def policy_for_tool(name: str) -> ToolPolicy:
    """Build validated policy metadata for one known tool name."""

    category = _category_for(name)
    effects = _effects_for(name)
    conditional = tuple(CONDITIONAL_EFFECTS.get(name, ()))
    conditional_kinds = {str(item.get("kind") or "") for item in conditional}
    unknown_conditional = conditional_kinds - SIDE_EFFECT_KINDS
    if unknown_conditional:
        raise ToolProfileError(
            f"Unknown conditional effects for {name}: {sorted(unknown_conditional)}"
        )
    risk = _risk_for(effects, name)
    profiles = _profiles_for(name, category, risk, effects)
    touches = tuple(sorted(CATEGORY_TOUCHES[category]))

    destructive_effects = {
        "debuggee.memory.write",
        "debuggee.module.inject",
        "debuggee.input",
        "host.user-input",
        "host.filesystem.write",
        "host.configuration.write",
        "kernel.driver.control",
        "unbounded.command",
    }
    destructive = bool(set(effects).intersection(destructive_effects)) or name in DESTRUCTIVE_NAMES
    read_only = not effects
    idempotent = read_only or name in IDEMPOTENT_MUTATIONS
    open_world = any(item != "mcp" for item in touches)

    return ToolPolicy(
        name=name,
        category=category,
        tags=_tags_for(name, category, effects, conditional),
        profiles=profiles,
        risk=risk,
        touches=touches,
        side_effects=effects,
        conditional_side_effects=conditional,
        requires=_requirements_for(name),
        read_only=read_only,
        destructive=destructive,
        idempotent=idempotent,
        open_world=open_world,
    )


def build_tool_catalog(
    registry: Mapping[str, Any] | Iterable[str],
    *,
    active_profile: str = DEFAULT_PROFILE,
) -> dict[str, Any]:
    """Build schema-v2 catalog for an exact, fully classified registry.

    Unknown and stale policies are rejected.  This makes a newly registered
    tool a deliberate policy decision instead of silently exposing it through a
    supposedly safe profile.
    """

    if active_profile not in PROFILE_NAMES:
        raise ToolProfileError(
            f"Unknown tool profile {active_profile!r}; expected one of {PROFILE_NAMES}"
        )
    actual = _registry_names(registry)
    known = known_tool_names()
    missing_policy = sorted(actual - known)
    stale_policy = sorted(known - actual)
    if missing_policy or stale_policy:
        parts = []
        if missing_policy:
            parts.append("missing policy: " + ", ".join(missing_policy))
        if stale_policy:
            parts.append("stale policy: " + ", ".join(stale_policy))
        raise ToolProfileError("Registry/profile inventory mismatch (" + "; ".join(parts) + ")")

    policies = {name: policy_for_tool(name) for name in sorted(actual)}
    metadata = {name: policy.as_dict() for name, policy in policies.items()}
    categories = {
        category: sorted(name for name, policy in policies.items() if policy.category == category)
        for category in CATEGORY_TOOLS
    }
    profiles = {
        profile: {
            "description": PROFILE_DESCRIPTIONS[profile],
            "count": sum(profile in policy.profiles for policy in policies.values()),
            "tools": sorted(name for name, policy in policies.items() if profile in policy.profiles),
        }
        for profile in PROFILE_NAMES
    }
    return {
        "ok": True,
        "schemaVersion": SCHEMA_VERSION,
        "count": len(actual),
        "tools": sorted(actual),
        "categories": categories,
        "defaultProfile": DEFAULT_PROFILE,
        "recommendedProfile": RECOMMENDED_PROFILE,
        "activeProfile": active_profile,
        "visibleTools": list(profiles[active_profile]["tools"]),
        "profiles": profiles,
        "toolMetadata": metadata,
    }


def visible_tool_names(catalog: Mapping[str, Any], profile: str) -> frozenset[str]:
    """Return the advertised names for one catalog profile."""

    if profile not in PROFILE_NAMES:
        raise ToolProfileError(
            f"Unknown tool profile {profile!r}; expected one of {PROFILE_NAMES}"
        )
    profiles = catalog.get("profiles")
    if not isinstance(profiles, Mapping) or not isinstance(profiles.get(profile), Mapping):
        raise ToolProfileError("Catalog has no valid profile table")
    tools = profiles[profile].get("tools")
    if not isinstance(tools, list):
        raise ToolProfileError(f"Catalog profile {profile!r} has no tool list")
    return frozenset(str(name) for name in tools)


def filter_mcp_tools(
    tools: Iterable[Any],
    catalog: Mapping[str, Any],
    profile: str,
) -> list[Any]:
    """Filter an MCP list-tools result without changing ToolManager registration."""

    visible = visible_tool_names(catalog, profile)
    result: list[Any] = []
    for tool in tools:
        name = tool.get("name") if isinstance(tool, Mapping) else getattr(tool, "name", None)
        if str(name or "") in visible:
            result.append(tool)
    return result


def apply_tool_metadata(
    mcp: Any,
    registry: Mapping[str, Any] | Iterable[str],
    *,
    active_profile: str = DEFAULT_PROFILE,
) -> dict[str, Any]:
    """Attach annotations and ``_meta`` data after all tools are registered.

    The function intentionally does not remove or replace a registered tool.
    It therefore remains compatible with existing decorators and direct
    ``call_tool`` users.  A server may separately use :func:`filter_mcp_tools`
    in its ``list_tools`` implementation.
    """

    catalog = build_tool_catalog(registry, active_profile=active_profile)
    manager = getattr(mcp, "_tool_manager", None)
    if manager is None or not callable(getattr(manager, "list_tools", None)):
        raise ToolProfileError("FastMCP tool manager is unavailable")

    registered = {str(tool.name): tool for tool in manager.list_tools()}
    expected = set(catalog["tools"])
    if set(registered) != expected:
        raise ToolProfileError("FastMCP manager and callable registry do not match")

    try:
        from mcp.types import ToolAnnotations
    except Exception as exc:  # pragma: no cover - dependency contract
        raise ToolProfileError("Installed MCP package has no ToolAnnotations") from exc

    for name, tool in registered.items():
        metadata = catalog["toolMetadata"][name]
        annotations = metadata["annotations"]
        tool.annotations = ToolAnnotations(**annotations)
        existing_meta = dict(getattr(tool, "meta", None) or {})
        existing_meta["x64dbg"] = {
            "schemaVersion": SCHEMA_VERSION,
            "resultContract": metadata["resultContract"],
            "legacyResultShim": dict(metadata["legacyResultShim"]),
            "category": metadata["category"],
            "tags": list(metadata["tags"]),
            "profiles": list(metadata["profiles"]),
            "risk": metadata["risk"],
            "touches": list(metadata["touches"]),
            "sideEffects": list(metadata["sideEffects"]),
            "conditionalSideEffects": list(metadata["conditionalSideEffects"]),
            "requires": list(metadata["requires"]),
        }
        tool.meta = existing_meta
    return catalog


__all__ = [
    "CATEGORY_TOOLS",
    "COMPACT_TOOLS",
    "DEFAULT_PROFILE",
    "PROFILE_NAMES",
    "RECOMMENDED_PROFILE",
    "RISK_LEVELS",
    "SCHEMA_VERSION",
    "RESULT_CONTRACT",
    "LEGACY_RESULT_SHIM",
    "SIDE_EFFECT_KINDS",
    "ToolPolicy",
    "ToolProfileError",
    "apply_tool_metadata",
    "build_tool_catalog",
    "filter_mcp_tools",
    "known_tool_names",
    "policy_for_tool",
    "visible_tool_names",
]
