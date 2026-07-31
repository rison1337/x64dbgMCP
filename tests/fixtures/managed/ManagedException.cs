using System;

internal static class ManagedExceptionFixture
{
    private static int Main()
    {
        try
        {
            throw new InvalidOperationException("x64dbgMCP managed correlation");
        }
        catch (Exception exception)
        {
            Console.WriteLine(
                "MANAGED_CLR_OK type={0} hresult=0x{1:X8}",
                exception.GetType().FullName,
                exception.HResult);
            return 0;
        }
    }
}
