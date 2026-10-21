# Runs INSIDE Windows Sandbox (run.cmd -> LogonCommand). Input: C:\in (read-only), output: C:\out (writable).
# The target is run only here, under Networking=Disable. This script is NEVER run on the host.
#
# Output integrity (the host verifies it with sandbox/integrity.py):
#  - C:\out and C:\in are open to EVERYONE inside the guest (labels/ACLs apply, but an unprivileged user can still write/read).
#    So C:\out CANNOT be trusted to stay untouched; every record is HMAC'd with a secret (nonce) the target cannot know.
#  - nonce: the host writes `in\nonce.txt`; this script reads it into memory, acknowledges with `out\ready.json`, WAITS until the HOST
#    DELETES the file, and starts the target only after that. The nonce is not on disk while the target runs; it cannot read the script's memory.
#  - the target runs as a non-admin local user (rhtgt), separate from the runner, with Low integrity; reading the runner's
#    memory (PROCESS_VM_READ) is denied for this user. The same user + Low IL alone is NOT ENOUGH:
#    a Low IL process could open the parent process.
#  - stdout/stderr is a PIPE held by the runner, not a target file; the target never touches output files.
#  - the target tree (all rhtgt processes) is killed after each case; in the seal phase the files are compared with the in-memory
#    values and rewritten if different (the target is dead).
# Contract:
#   ready.json     nonce-read acknowledgement (nonce_commit)                  (first)
#   session.json   the target's SHA-256 inside the sandbox + integrity record  (after the nonce is deleted)
#   cNNN.stdout / cNNN.stderr / cNNN.json                             (each case; .json LAST, atomic; carries the integrity record)
#   fatal.json     if the guest hits an unexpected error
#   done.json      last; run_id + case count + mac
$ErrorActionPreference = 'Continue'
$in = 'C:\in'; $out = 'C:\out'; $work = 'C:\work'
$utf8 = New-Object System.Text.UTF8Encoding($false)

$csharp = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading;

public sealed class RhCap {
    readonly Stream s; readonly long cap; readonly MemoryStream ms = new MemoryStream();
    long total; volatile bool over; readonly Thread t;
    public RhCap(Stream s, long cap) {
        this.s = s; this.cap = cap;
        t = new Thread(Pump); t.IsBackground = true; t.Start();
    }
    void Pump() {
        var b = new byte[16384];
        try {
            int n;
            while ((n = s.Read(b, 0, b.Length)) > 0) {
                lock (ms) {
                    long room = cap - ms.Length;
                    if (room > 0) ms.Write(b, 0, (int)Math.Min(room, (long)n));
                    total += n;
                    if (total > cap) over = true;
                }
            }
        } catch (Exception) { }
    }
    public bool Over { get { return over; } }
    public bool Join(int msec) { return t.Join(msec); }
    public long Total { get { lock (ms) { return total; } } }
    public byte[] Bytes() { lock (ms) { return ms.ToArray(); } }
}

public sealed class RhResult {
    public bool LaunchFailed; public string LaunchError = "";
    public bool TimedOut; public bool Truncated; public bool HasExit; public int ExitCode;
    public long ElapsedMs; public byte[] Out = new byte[0]; public byte[] Err = new byte[0];
    public long OutTotal; public long ErrTotal;
    public string TargetIntegrity = "unknown"; public string TargetSid = "";
}

public static class RhRun {
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int ret);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern uint SetErrorMode(uint mode);

    // System error dialogs (missing DLL "cannot run code", GP fault window, file-open error) must not make the target
    // wait forever: SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX. The target starts as a child of this
    // process (error mode is inherited); a missing DLL ends with exit code 0xC0000135 instead of a window.
    public static void NoErrorUi() { SetErrorMode(0x8003); }

    static IntPtr TokenInfo(IntPtr tok, int cls) {
        int len;
        GetTokenInformation(tok, cls, IntPtr.Zero, 0, out len);
        if (len <= 0) return IntPtr.Zero;
        IntPtr buf = Marshal.AllocHGlobal(len);
        if (!GetTokenInformation(tok, cls, buf, len, out len)) { Marshal.FreeHGlobal(buf); return IntPtr.Zero; }
        return buf;
    }
    // CharSet.Unicode is required: the default ANSI variant is selected and PtrToStringUni yields garbage (SID mismatch, KillUser kills nothing).
    static string TokenSid(IntPtr tok) {
        IntPtr buf = TokenInfo(tok, 1);   // TokenUser
        if (buf == IntPtr.Zero) return "";
        try {
            IntPtr sid = Marshal.ReadIntPtr(buf), str;
            if (!ConvertSidToStringSid(sid, out str)) return "";
            string s = Marshal.PtrToStringUni(str); LocalFree(str); return s;
        } finally { Marshal.FreeHGlobal(buf); }
    }
    static string TokenIl(IntPtr tok) {
        IntPtr buf = TokenInfo(tok, 25);  // TokenIntegrityLevel
        if (buf == IntPtr.Zero) return "unknown";
        try {
            IntPtr sid = Marshal.ReadIntPtr(buf);
            int n = Marshal.ReadByte(sid, 1);
            int rid = Marshal.ReadInt32(sid, 8 + 4 * (n - 1));
            return rid < 0x2000 ? "low" : rid < 0x3000 ? "medium" : rid < 0x4000 ? "high" : "system";
        } finally { Marshal.FreeHGlobal(buf); }
    }

    // Kills all processes owned by sid; returns the number of live processes found in this pass. 0 = none left.
    public static int KillUser(string sid) {
        int found = 0;
        foreach (var p in Process.GetProcesses()) {
            IntPtr h = IntPtr.Zero, tok = IntPtr.Zero;
            try {
                h = OpenProcess(0x1001, false, p.Id);   // QUERY_LIMITED_INFORMATION | TERMINATE
                if (h == IntPtr.Zero) continue;
                if (!OpenProcessToken(h, 8, out tok)) continue;
                if (TokenSid(tok) != sid) continue;
                found++;
                TerminateProcess(h, 1);
            } catch (Exception) { }
            finally { if (tok != IntPtr.Zero) CloseHandle(tok); if (h != IntPtr.Zero) CloseHandle(h); p.Dispose(); }
        }
        return found;
    }
    public static int KillUserAll(string sid, int waitMs) {
        var sw = Stopwatch.StartNew(); int left;
        while ((left = KillUser(sid)) > 0 && sw.ElapsedMilliseconds < waitMs) Thread.Sleep(100);
        return left;
    }

    public static RhResult Run(string exe, string args, string workdir, string user, string domain, SecureString pw,
                               byte[] stdin, long cap, long timeoutMs, string tmpdir, string sid) {
        var r = new RhResult();
        var psi = new ProcessStartInfo(exe, args ?? "");
        psi.WorkingDirectory = workdir; psi.UseShellExecute = false; psi.CreateNoWindow = true;
        psi.RedirectStandardInput = true; psi.RedirectStandardOutput = true; psi.RedirectStandardError = true;
        // stdin is passed as raw bytes: the StreamWriter's default encoding (if the console is UTF-8) adds a BOM (EF BB BF) on first write.
        // The writer is used only to write bytes to BaseStream; a BOM-less encoding prevents that too.
        // StandardInputEncoding needs .NET 4.6.1+; on older Framework it is a compile error -> use reflection, else Console.InputEncoding.
        var sip = typeof(ProcessStartInfo).GetProperty("StandardInputEncoding");
        if (sip != null) sip.SetValue(psi, new System.Text.UTF8Encoding(false), null);
        else { try { Console.InputEncoding = new System.Text.UTF8Encoding(false); } catch (Exception) { } }
        psi.UserName = user; psi.Domain = domain; psi.Password = pw; psi.LoadUserProfile = false;
        foreach (var k in new[] { "TEMP", "TMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA" }) psi.EnvironmentVariables[k] = tmpdir;
        psi.EnvironmentVariables["USERNAME"] = user;
        Process p;
        var sw = Stopwatch.StartNew();
        try { p = Process.Start(psi); }
        catch (Exception e) { r.LaunchFailed = true; r.LaunchError = e.Message; r.ElapsedMs = sw.ElapsedMilliseconds; return r; }
        try {
            IntPtr tok;
            if (OpenProcessToken(p.Handle, 8, out tok)) { r.TargetIntegrity = TokenIl(tok); r.TargetSid = TokenSid(tok); CloseHandle(tok); }
        } catch (Exception) { }
        var co = new RhCap(p.StandardOutput.BaseStream, cap);
        var ce = new RhCap(p.StandardError.BaseStream, cap);
        var tw = new Thread(() => {
            try { if (stdin.Length > 0) p.StandardInput.BaseStream.Write(stdin, 0, stdin.Length); p.StandardInput.BaseStream.Flush(); }
            catch (Exception) { }
            try { p.StandardInput.Close(); } catch (Exception) { }
        });
        tw.IsBackground = true; tw.Start();
        bool killed = false;
        while (true) {
            if (p.WaitForExit(25)) break;
            if (sw.ElapsedMilliseconds >= timeoutMs) { r.TimedOut = true; killed = true; break; }
            if (co.Over || ce.Over) { r.Truncated = true; killed = true; break; }
        }
        if (p.HasExited) { killed = false; r.TimedOut = false; }
        r.ElapsedMs = sw.ElapsedMilliseconds;
        if (!killed) { r.HasExit = true; r.ExitCode = p.ExitCode; co.Join(500); ce.Join(500); }
        KillUserAll(sid, 20000);   // all processes of the target user, including spawned children
        co.Join(3000); ce.Join(3000);
        r.Out = co.Bytes(); r.Err = ce.Bytes(); r.OutTotal = co.Total; r.ErrTotal = ce.Total;
        if (r.OutTotal > cap || r.ErrTotal > cap) r.Truncated = true;
        try { p.Dispose(); } catch (Exception) { }
        return r;
    }
}
'@

function Save-Bytes($name, [byte[]]$bytes) {
    # the host may be reading the file right now (sharing violation): retry at short intervals
    for ($try = 0; $true; $try++) {
        try {
            $tmp = "$out\$name.tmp"
            [IO.File]::WriteAllBytes($tmp, $bytes)
            Move-Item -Force -LiteralPath $tmp -Destination "$out\$name" -ErrorAction Stop
            return
        } catch { if ($try -ge 30) { throw }; Start-Sleep -Milliseconds 100 }
    }
}
function Save-Text($name, $text) { Save-Bytes $name ($utf8.GetBytes($text)) }

function Sha256Hex([byte[]]$b) {
    $h = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($h.ComputeHash($b)) -replace '-', '').ToLower() } finally { $h.Dispose() }
}
function Hmac-Hex([string]$key, [string]$msg) {
    $h = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (, $utf8.GetBytes($key))
    try { return ([BitConverter]::ToString($h.ComputeHash($utf8.GetBytes($msg))) -replace '-', '').ToLower() } finally { $h.Dispose() }
}
function B01($v) { if ($v) { return '1' } else { return '0' } }

function Read-Shared($path) {
    $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite,Delete')
    try { $ms = New-Object IO.MemoryStream; $fs.CopyTo($ms); return $ms.ToArray() } finally { $fs.Dispose() }
}

$script:fatalKey = $null
function Save-Fatal($msg) {
    $d = [ordered]@{ error = [string]$msg }
    if ($script:fatalKey) { $d.mac = (Hmac-Hex $script:fatalKey ('rh-integrity/1|fatal|' + [string]$msg)) }
    Save-Text 'fatal.json' (ConvertTo-Json -Compress -InputObject $d)
}

try {
    $spec = [IO.File]::ReadAllText("$in\cases.json", $utf8) | ConvertFrom-Json
    $runId = [string]$spec.run_id
    $cap = [int64]$spec.max_stream_bytes
    $exe = [string]$spec.exe

    # --- 1. nonce: read into memory, acknowledge, wait until the host deletes the file (target does not exist yet)
    $nonce = $utf8.GetString((Read-Shared "$in\nonce.txt")).Trim()
    if ($nonce -notmatch '^[0-9a-f]{64}$') { throw 'nonce.txt invalid' }
    $script:fatalKey = $nonce
    $commit = Sha256Hex ($utf8.GetBytes('rh-nonce-commit/1:' + $nonce))
    Save-Text 'ready.json' (ConvertTo-Json -Compress -InputObject ([ordered]@{ run_id = $runId; nonce_commit = $commit }))
    $wait = [Diagnostics.Stopwatch]::StartNew()
    while (Test-Path -LiteralPath "$in\nonce.txt") {
        if ($wait.Elapsed.TotalSeconds -gt 150) { throw 'host did not delete the nonce file' }
        Start-Sleep -Milliseconds 100
    }

    # --- 2. compile + target user (non-admin, only for this session)
    try { Add-Type -TypeDefinition $csharp -Language CSharp -ErrorAction Stop }
    catch { throw ('Add-Type compile error: ' + $_.Exception.Message + ' | ' + (($_.Exception.Data.Values | ForEach-Object { [string]$_ }) -join ' ; ')) }
    Start-Service seclogon -ErrorAction Stop
    $user = 'rhtgt'
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $rb = New-Object byte[] 24; $rng.GetBytes($rb)
    $plain = 'Aa1!' + [Convert]::ToBase64String($rb)
    $sec = ConvertTo-SecureString $plain -AsPlainText -Force
    $plain = $null
    $null = New-LocalUser -Name $user -Password $sec -AccountNeverExpires -PasswordNeverExpires -ErrorAction Stop
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $user -ErrorAction Stop
    $sid = (Get-LocalUser -Name $user).SID.Value
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.SID.Value })
    if ($admins -contains $sid) { throw 'target user is in the administrators group' }
    try { [RhRun]::NoErrorUi() } catch { }
    foreach ($kv in @(@('HKLM:\SYSTEM\CurrentControlSet\Control\Windows', 'ErrorMode', 2),
                      @('HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting', 'DontShowUI', 1),
                      @('HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting', 'Disabled', 1))) {
        try { if (-not (Test-Path -LiteralPath $kv[0])) { New-Item -Path $kv[0] -ErrorAction SilentlyContinue | Out-Null }; Set-ItemProperty -Path $kv[0] -Name $kv[1] -Value $kv[2] -Type DWord -ErrorAction Stop } catch { }
    }
    New-Item -ItemType Directory -Force $work | Out-Null
    # open C:\work only to admin/SYSTEM: the target user can reach nothing outside the case folder
    & icacls.exe $work /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'could not restrict ACL on C:\work' }

    $h = Get-FileHash -Algorithm SHA256 -LiteralPath "$in\bin\$exe"
    $tsha = $h.Hash.ToLower()
    $sessMac = Hmac-Hex $nonce ("rh-integrity/1|session|$runId|$tsha|1|1")
    $sessText = (ConvertTo-Json -Compress -InputObject ([ordered]@{
        run_id = $runId; target_sha256 = $tsha; os = [Environment]::OSVersion.VersionString
        integrity = [ordered]@{ version = 1; nonce_commit = $commit; separate_user = $true; low_il_label = $true; mac = $sessMac } }))
    Save-Text 'session.json' $sessText

    $mem = @{}      # tag -> @{ so; se; macs ... } correct in-memory values (for the seal)
    $caseMacs = New-Object System.Collections.ArrayList
    foreach ($c in $spec.cases) {
        $idx = [int]$c.index
        $tag = 'c{0:D3}' -f $idx
        $w = "$work\$tag"
        $res = [ordered]@{ index = $idx; exit_code = $null; timed_out = $false; truncated = $false
                           launch_error = $null; elapsed_ms = 0; stdout_total = 0; stderr_total = 0 }
        $o = [byte[]]@(); $e = [byte[]]@(); $til = 'unknown'; $su = $false
        try {
            # each case runs in a clean copy: files the target wrote (e.g. trial.txt) do not carry over between cases
            New-Item -ItemType Directory -Force "$w\tmp" | Out-Null
            Copy-Item -Recurse -Force -Path "$in\bin\*" -Destination $w
            & icacls.exe $w /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${sid}:(OI)(CI)M" /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'could not restrict ACL on case folder' }
            & icacls.exe $w /setintegritylevel '(OI)(CI)low' /Q | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'could not label case folder Low integrity' }
            $stdin = [Convert]::FromBase64String([string]$c.stdin_b64)
            $limit = [int64]([double]$c.timeout_s * 1000)
            if ($c.observe) {
                # observed execution (dynamic observation): the pinned tracer runs as the target user at Medium IL
                # from C:\work\tools (NOT low-labeled) and starts the target as its Low-IL debuggee; the case's stdout is
                # the trace (runner pipe, MAC'd like any case). The target is the same per-case Low-labeled copy.
                $tool = [string]$c.observe.tool
                if ($tool -notmatch '^[A-Za-z0-9._-]{1,64}\.exe$') { throw 'observe tool name invalid' }
                $tdir = "$work\tools"
                if (-not (Test-Path -LiteralPath "$tdir\$tool")) {
                    New-Item -ItemType Directory -Force $tdir | Out-Null
                    Copy-Item -Force -LiteralPath "$in\tools\$tool" -Destination "$tdir\$tool"
                    & icacls.exe $tdir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "*${sid}:(OI)(CI)RX" /Q | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw 'could not restrict ACL on the tools folder' }
                }
                if ((Get-FileHash -Algorithm SHA256 -LiteralPath "$tdir\$tool").Hash.ToLower() -ne [string]$c.observe.sha256) {
                    throw 'observe tool SHA-256 mismatch inside the sandbox'
                }
                $targs = ([string]$c.observe.args + ' ' + "$w\$exe" + ' ' + [string]$c.argv_line).TrimEnd()
                $r = [RhRun]::Run("$tdir\$tool", $targs, $w, $user, $env:COMPUTERNAME, $sec, $stdin, $cap, $limit, "$w\tmp", $sid)
            } else {
                $r = [RhRun]::Run("$w\$exe", [string]$c.argv_line, $w, $user, $env:COMPUTERNAME, $sec, $stdin, $cap, $limit, "$w\tmp", $sid)
            }
            $res.elapsed_ms = [int]$r.ElapsedMs
            if ($r.LaunchFailed) { $res.launch_error = [string]$r.LaunchError }
            else {
                $res.timed_out = [bool]$r.TimedOut; $res.truncated = [bool]$r.Truncated
                if ($r.HasExit -and -not $r.TimedOut -and -not $r.Truncated) { $res.exit_code = [int]$r.ExitCode }
                if ($r.HasExit -and $r.Truncated) { $res.exit_code = $null }
                $o = [byte[]]$r.Out; $e = [byte[]]$r.Err
                $res.stdout_total = [int64]$r.OutTotal; $res.stderr_total = [int64]$r.ErrTotal
                $til = [string]$r.TargetIntegrity
                $su = ($r.TargetSid -ne '' -and $r.TargetSid -eq $sid)
            }
        } catch { $res.launch_error = $_.Exception.Message }
        [void][RhRun]::KillUserAll($sid, 20000)
        $osha = Sha256Hex $o; $esha = Sha256Hex $e
        $ec = '-'; if ($null -ne $res.exit_code) { $ec = [string]$res.exit_code }
        $lesha = '-'; if ($res.launch_error) { $lesha = Sha256Hex ($utf8.GetBytes([string]$res.launch_error)) }
        $canon = "rh-integrity/1|case|$runId|$idx|$osha|$esha|$ec|$(B01 $res.timed_out)|$(B01 $res.truncated)|$($res.stdout_total)|$($res.stderr_total)|$lesha|$($res.elapsed_ms)|$til|$(B01 $su)"
        $mac = Hmac-Hex $nonce $canon
        $res.integrity = [ordered]@{ version = 1; case_id = "${runId}:$idx"; stdout_sha256 = $osha; stderr_sha256 = $esha
                                      exit_code = $res.exit_code; nonce_commit = $commit; target_integrity = $til
                                      separate_user = $su; mac = $mac }
        $metaText = ConvertTo-Json -Compress -Depth 4 -InputObject $res
        $mem[$tag] = @{ o = $o; e = $e; meta = $metaText }
        [void]$caseMacs.Add($mac)
        Save-Bytes "$tag.stdout" $o
        Save-Bytes "$tag.stderr" $e
        Save-Text "$tag.json" $metaText
    }

    # --- 3. seal: close the target user, compare files with memory, rewrite if different
    [void][RhRun]::KillUserAll($sid, 20000)
    try { Disable-LocalUser -Name $user -ErrorAction Stop } catch { }
    [void][RhRun]::KillUserAll($sid, 20000)
    function Fix-File($name, [byte[]]$want) {
        $p = "$out\$name"; $good = $false
        try {
            $it = Get-Item -LiteralPath $p -Force -ErrorAction Stop
            if (-not $it.PSIsContainer -and -not ($it.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                $good = ((Sha256Hex ([byte[]](Read-Shared $p))) -eq (Sha256Hex $want))
            }
        } catch { }
        if (-not $good) {
            try { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop } catch { }
            Save-Bytes $name $want
        }
    }
    Fix-File 'session.json' ($utf8.GetBytes($sessText))
    foreach ($k in $mem.Keys) {
        Fix-File "$k.stdout" $mem[$k].o
        Fix-File "$k.stderr" $mem[$k].e
        Fix-File "$k.json" ($utf8.GetBytes($mem[$k].meta))
    }
    if (Test-Path -LiteralPath "$out\fatal.json") { Remove-Item -LiteralPath "$out\fatal.json" -Recurse -Force -ErrorAction SilentlyContinue }
    $n = @($spec.cases).Count
    $dmac = Hmac-Hex $nonce ("rh-integrity/1|done|$runId|$n|" + (Sha256Hex ($utf8.GetBytes(($caseMacs -join ',')))))
    Save-Text 'done.json' (ConvertTo-Json -Compress -InputObject ([ordered]@{ run_id = $runId; cases = $n; mac = $dmac }))
} catch {
    Save-Fatal ($_.Exception.Message + ' (guest.ps1 line ' + $_.InvocationInfo.ScriptLineNumber + ')')
}
