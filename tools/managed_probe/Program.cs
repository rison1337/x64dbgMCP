using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using Microsoft.Diagnostics.Runtime;

namespace X64dbgMcp.ManagedProbe;

internal static class Program
{
    private sealed class Options
    {
        public int Pid { get; set; }
        public int MaxThreads { get; set; } = 256;
        public int MaxFrames { get; set; } = 256;
        public int MaxModules { get; set; } = 4096;
        public int MaxMaps { get; set; } = 4096;
        public ulong? InstructionPointer { get; set; }
        public uint? MetadataToken { get; set; }
        public string Module { get; set; } = "";
    }

    public static int Main(string[] args)
    {
        try
        {
            Options options = Parse(args);
            object report = Probe(options);
            Console.Out.WriteLine(
                JsonSerializer.Serialize(
                    report,
                    new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                        WriteIndented = false,
                    }
                )
            );
            return 0;
        }
        catch (Exception ex)
        {
            Console.Out.WriteLine(
                JsonSerializer.Serialize(
                    new
                    {
                        schema = "x64dbg-mcp-managed-probe-v1",
                        ok = false,
                        error = new
                        {
                            code = "MANAGED_PROBE_FAILED",
                            message = ex.Message,
                            type = ex.GetType().FullName,
                        },
                    }
                )
            );
            return 1;
        }
    }

    private static Options Parse(string[] args)
    {
        Options result = new();
        for (int index = 0; index < args.Length; index++)
        {
            string name = args[index];
            string Value()
            {
                if (++index >= args.Length)
                    throw new ArgumentException($"Missing value for {name}.");
                return args[index];
            }

            switch (name)
            {
                case "--pid":
                    result.Pid = int.Parse(Value(), CultureInfo.InvariantCulture);
                    break;
                case "--max-threads":
                    result.MaxThreads = Bounded(Value(), 1, 4096, name);
                    break;
                case "--max-frames":
                    result.MaxFrames = Bounded(Value(), 1, 4096, name);
                    break;
                case "--max-modules":
                    result.MaxModules = Bounded(Value(), 1, 100_000, name);
                    break;
                case "--max-maps":
                    result.MaxMaps = Bounded(Value(), 1, 100_000, name);
                    break;
                case "--ip":
                    result.InstructionPointer = ParseUnsigned(Value(), name);
                    break;
                case "--token":
                    result.MetadataToken = checked((uint)ParseUnsigned(Value(), name));
                    break;
                case "--module":
                    result.Module = Value();
                    break;
                default:
                    throw new ArgumentException($"Unknown argument: {name}");
            }
        }

        if (result.Pid <= 0)
            throw new ArgumentException("--pid must be a positive process identifier.");
        return result;
    }

    private static int Bounded(string value, int minimum, int maximum, string name)
    {
        int parsed = int.Parse(value, CultureInfo.InvariantCulture);
        if (parsed < minimum || parsed > maximum)
            throw new ArgumentOutOfRangeException(name, $"{name} must be in {minimum}..{maximum}.");
        return parsed;
    }

    private static ulong ParseUnsigned(string value, string name)
    {
        string text = value.Trim();
        NumberStyles style = NumberStyles.Integer;
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            text = text.Substring(2);
            style = NumberStyles.AllowHexSpecifier;
        }
        if (!ulong.TryParse(text, style, CultureInfo.InvariantCulture, out ulong parsed))
            throw new ArgumentException($"{name} is not a valid unsigned integer.");
        return parsed;
    }

    private static object Probe(Options options)
    {
        Process process = Process.GetProcessById(options.Pid);
        DateTime startTime = process.StartTime.ToUniversalTime();
        string imagePath = Safe<string?>(() => process.MainModule?.FileName, "") ?? "";
        bool processResponding = Safe(() => process.Responding, false);

        // suspend=false is intentional.  x64dbg owns the debug port and the MCP
        // contract requires the target to already be paused before this sidecar
        // is started.  ClrMD therefore performs a read-only memory attach.
        using DataTarget target = DataTarget.AttachToProcess(options.Pid, suspend: false);
        List<object> runtimes = new();
        List<object> resolutions = new();
        int runtimeIndex = 0;
        foreach (ClrInfo info in target.ClrVersions)
        {
            using ClrRuntime runtime = info.CreateRuntime();
            List<object> domains = ReadDomains(runtime, options);
            List<object> runtimeModules = ReadRuntimeModules(runtime, options);
            List<object> threads = new();
            Dictionary<string, object> methods = new(StringComparer.Ordinal);

            foreach (ClrThread thread in runtime.Threads.Take(options.MaxThreads))
            {
                List<object> frames = new();
                foreach (ClrStackFrame frame in thread.EnumerateStackTrace(false, options.MaxFrames))
                {
                    ClrMethod? method = frame.Method;
                    object? methodRecord = method is null ? null : ReadMethod(method, options);
                    if (method is not null && methodRecord is not null)
                    {
                        string key = MethodKey(method);
                        methods[key] = methodRecord;
                    }
                    frames.Add(
                        new
                        {
                            instructionPointer = Hex(frame.InstructionPointer),
                            stackPointer = Hex(frame.StackPointer),
                            kind = frame.Kind.ToString(),
                            frameName = frame.FrameName,
                            method = methodRecord,
                        }
                    );
                }

                ClrException? current = Safe<ClrException?>(() => thread.CurrentException, null);
                threads.Add(
                    new
                    {
                        address = Hex(thread.Address),
                        osThreadId = thread.OSThreadId,
                        managedThreadId = thread.ManagedThreadId,
                        state = thread.State.ToString(),
                        isAlive = thread.IsAlive,
                        isFinalizer = thread.IsFinalizer,
                        lockCount = thread.LockCount,
                        stackBase = Hex(thread.StackBase),
                        stackLimit = Hex(thread.StackLimit),
                        currentException = current is null
                            ? null
                            : new
                            {
                                address = Hex(current.Address),
                                type = current.Type?.Name,
                                message = Safe(() => current.Message, null),
                                hResult = $"0x{unchecked((uint)current.HResult):X8}",
                            },
                        frames,
                        frameCount = frames.Count,
                    }
                );
            }

            if (options.InstructionPointer.HasValue)
            {
                ClrMethod? method = runtime.GetMethodByInstructionPointer(
                    options.InstructionPointer.Value
                );
                resolutions.Add(
                    new
                    {
                        runtimeIndex,
                        query = new
                        {
                            instructionPointer = Hex(options.InstructionPointer.Value),
                        },
                        found = method is not null,
                        method = method is null ? null : ReadMethod(method, options),
                    }
                );
            }

            if (options.MetadataToken.HasValue)
            {
                List<object> tokenMatches = methods.Values
                    .Where(
                        value =>
                            ReadAnonymousToken(value) == options.MetadataToken.Value
                            && ModuleMatches(value, options.Module)
                    )
                    .ToList();
                resolutions.Add(
                    new
                    {
                        runtimeIndex,
                        query = new
                        {
                            metadataToken = $"0x{options.MetadataToken.Value:X8}",
                            module = options.Module,
                        },
                        found = tokenMatches.Count > 0,
                        scope = "active-managed-stack",
                        methods = tokenMatches,
                    }
                );
            }

            runtimes.Add(
                new
                {
                    index = runtimeIndex,
                    version = info.Version.ToString(),
                    flavor = info.Flavor.ToString(),
                    isSingleFile = info.IsSingleFile,
                    runtimeModule = new
                    {
                        path = info.ModuleInfo.FileName,
                        imageBase = Hex(info.ModuleInfo.ImageBase),
                    },
                    isThreadSafe = runtime.IsThreadSafe,
                    appDomains = domains,
                    modules = runtimeModules,
                    threads,
                    methods = methods.Values.ToList(),
                    counts = new
                    {
                        appDomains = domains.Count,
                        modules = runtimeModules.Count,
                        threads = threads.Count,
                        activeStackMethods = methods.Count,
                    },
                }
            );
            runtimeIndex++;
        }

        return new
        {
            schema = "x64dbg-mcp-managed-probe-v1",
            version = 1,
            ok = true,
            process = new
            {
                pid = options.Pid,
                imagePath,
                startTimeUtc = startTime.ToString("O", CultureInfo.InvariantCulture),
                responding = processResponding,
                architecture = target.DataReader.Architecture.ToString(),
            },
            attach = new
            {
                mode = "passive-read-only",
                targetMustAlreadyBePaused = true,
                suspendedByProbe = false,
            },
            runtimes,
            resolutions,
            counts = new
            {
                runtimes = runtimes.Count,
                resolutions = resolutions.Count,
            },
            limitations = new
            {
                mutation = false,
                managedBreakpoints = false,
                locals = false,
                tokenResolutionScope = "active-managed-stack",
            },
        };
    }

    private static List<object> ReadDomains(ClrRuntime runtime, Options options)
    {
        List<object> result = new();
        foreach (ClrAppDomain domain in runtime.AppDomains)
        {
            List<object> modules = domain.Modules
                .Take(options.MaxModules)
                .Select(ReadModule)
                .ToList();
            result.Add(
                new
                {
                    address = Hex(domain.Address),
                    id = domain.Id,
                    name = domain.Name,
                    applicationBase = Safe(() => domain.ApplicationBase, null),
                    configurationFile = Safe(() => domain.ConfigurationFile, null),
                    modules,
                    moduleCount = modules.Count,
                }
            );
        }
        return result;
    }

    private static List<object> ReadRuntimeModules(ClrRuntime runtime, Options options)
    {
        return runtime
            .EnumerateModules()
            .Take(options.MaxModules)
            .Select(ReadModule)
            .ToList();
    }

    private static object ReadModule(ClrModule module)
    {
        return new
        {
            address = Hex(module.Address),
            imageBase = Hex(module.ImageBase),
            size = module.Size,
            name = module.Name,
            assemblyName = module.AssemblyName,
            isDynamic = module.IsDynamic,
            isPeFile = module.IsPEFile,
            layout = module.Layout.ToString(),
            metadataAddress = Hex(module.MetadataAddress),
            metadataLength = module.MetadataLength,
            appDomain = module.AppDomain?.Name,
        };
    }

    private static object ReadMethod(ClrMethod method, Options options)
    {
        HotColdRegions regions = method.HotColdInfo;
        ILInfo? il = Safe<ILInfo?>(() => method.GetILInfo(), null);
        List<object> maps = method.ILOffsetMap
            .Take(options.MaxMaps)
            .Select(
                map =>
                    (object)
                        new
                        {
                            ilOffset = map.ILOffset,
                            startAddress = Hex(map.StartAddress),
                            endAddress = Hex(map.EndAddress),
                        }
            )
            .ToList();
        return new
        {
            methodDesc = Hex(method.MethodDesc),
            metadataToken = $"0x{unchecked((uint)method.MetadataToken):X8}",
            name = method.Name,
            signature = method.Signature,
            declaringType = method.Type?.Name,
            module = method.Type?.Module?.Name,
            moduleImageBase = method.Type?.Module is null
                ? null
                : Hex(method.Type.Module.ImageBase),
            nativeCode = Hex(method.NativeCode),
            compilationType = method.CompilationType.ToString(),
            hotCold = new
            {
                hotStart = Hex(regions.HotStart),
                hotSize = regions.HotSize,
                coldStart = Hex(regions.ColdStart),
                coldSize = regions.ColdSize,
            },
            il = il is null
                ? null
                : new
                {
                    address = Hex(il.Address),
                    length = il.Length,
                    flags = il.Flags,
                    localVarSignatureToken = $"0x{unchecked((uint)il.LocalVarSignatureToken):X8}",
                },
            ilToNativeMap = maps,
            ilToNativeMapCount = maps.Count,
        };
    }

    private static string MethodKey(ClrMethod method)
    {
        return string.Join(
            ":",
            Hex(method.MethodDesc),
            unchecked((uint)method.MetadataToken).ToString("X8", CultureInfo.InvariantCulture),
            Hex(method.NativeCode)
        );
    }

    private static uint ReadAnonymousToken(object value)
    {
        JsonElement element = JsonSerializer.SerializeToElement(value);
        string text = element.GetProperty("metadataToken").GetString() ?? "0";
        return checked((uint)ParseUnsigned(text, "metadataToken"));
    }

    private static bool ModuleMatches(object value, string expected)
    {
        if (string.IsNullOrWhiteSpace(expected))
            return true;
        JsonElement element = JsonSerializer.SerializeToElement(value);
        string actual = element.GetProperty("module").GetString() ?? "";
        string expectedName = Path.GetFileName(expected);
        string actualName = Path.GetFileName(actual);
        return actual.Equals(expected, StringComparison.OrdinalIgnoreCase)
            || actualName.Equals(expectedName, StringComparison.OrdinalIgnoreCase);
    }

    private static string Hex(ulong value) => $"0x{value:X}";

    private static T Safe<T>(Func<T> callback, T fallback)
    {
        try
        {
            return callback();
        }
        catch
        {
            return fallback;
        }
    }
}
