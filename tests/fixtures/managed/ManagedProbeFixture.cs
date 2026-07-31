using System;
using System.IO;
using System.Reflection;
using System.Threading;

internal static class ManagedProbeFixture
{
    private static Assembly dynamicAssembly;

    private static int ManagedWork(int value)
    {
        Console.WriteLine(
            "MANAGED_PROBE_READY tid={0} value={1}",
            Thread.CurrentThread.ManagedThreadId,
            value);
        string line = Console.ReadLine();
        Console.WriteLine("MANAGED_PROBE_RESUME input={0}", line ?? "<eof>");
        return value + 1;
    }

    private static int Main(string[] args)
    {
        int dynamicResult = BuildDynamicMethod(41);
        int result = ManagedWork(41);
        int second = ManagedWork(99);
        Console.WriteLine(
            "MANAGED_PROBE_OK result={0} second={1} dynamic={2}",
            result,
            second,
            dynamicResult);
        return result == 42 && second == 100 && dynamicResult == 42 ? 0 : 9;
    }

    private static int BuildDynamicMethod(int value)
    {
        byte[] image;
        using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(
            "ManagedProbeDynamicPayload.bin"))
        {
            if (stream == null)
                throw new InvalidOperationException("Embedded managed payload is missing.");
            image = new byte[stream.Length];
            int offset = 0;
            while (offset < image.Length)
            {
                int read = stream.Read(image, offset, image.Length - offset);
                if (read <= 0)
                    throw new EndOfStreamException();
                offset += read;
            }
        }
        dynamicAssembly = Assembly.Load(image);
        Type type = dynamicAssembly.GetType("ManagedProbeDynamicPayload", true);
        MethodInfo method = type.GetMethod("AddOne", BindingFlags.Public | BindingFlags.Static);
        return (int)method.Invoke(null, new object[] { value });
    }
}
