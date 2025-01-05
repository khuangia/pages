# 从进程创建解析系统机制

- ## 开头

开发设计过程中，遇到许多偶发未知问题，往往是对运行在底层的操作系统实现模糊引起，理解操作系统如何设计，是好的架构设计和一些疑难问题解决的必要条件

以创建进程为例，探讨下操作系统优秀的设计

大概的讲，进程创建就是 Windows 按照 PE 格式解析目标文件，生成一个进程结构体管理进程系统资源，再创建一条线程关联到进程主程序入口点代码，将Cpu 寄存器切换为线程的 Context，通俗意义的进程就跑起来了

参考基于 ida Windows 11 22H2、wrk 与Reactos，**内容不保真**

- ## 执行开始

在Windows 中有多个API 可以创建进程，如 WinExec/ShellExecute/CreateProcess，实际WinExec 是CreateProcess 的封装，而ShellExecute 除去与桌面环境的诸多交互，同样调用 CreateProcess 函数

+ WinExec

```other
- WinExec 会等待进程进入 Idle 状态再返回，最多等待30 秒

UINT __stdcall WinExec(LPCSTR lpCmdLine, UINT uCmdShow) {
  ...
  if ( (uCmdShow & 0x80000000) == 0 ) {
LABEL_7:
    memset_0(&StartupInfo, 0, sizeof(StartupInfo));
    StartupInfo.dwFlags = 1;
    StartupInfo.wShowWindow = uCmdShow_1;
    StartupInfo.cb = dwCreationFlags != 0 ? 112 : 104;
    if ( CreateProcessA(
           0i64,
           (LPSTR)lpCmdLine,
           ...
           &StartupInfo,
           &ProcessInformation) ) {
      if ( UserWaitForInputIdleRoutine )
        UserWaitForInputIdleRoutine(ProcessInformation.hProcess, 30000i64);
	...
```

+ ShellExecute

```other
- 主线程
00 SHELL32!CShellExecute::_RunThreadMaybeWait -> 启动新线程
01 SHELL32!CShellExecute::ExecuteNormal+0x892
02 SHELL32!ShellExecuteNormal+0x151
03 SHELL32!ShellExecuteExW+0xfc

- 为了防止进程创建过程卡住，以新线程执行创建动作是有必要的
01 KERNELBASE!CreateProcessW+0x66
02 KERNEL32!CreateProcessWStub+0x54
03 windows_storage!CInvokeCreateProcessVerb::CallCreateProcess+0x5be
04 windows_storage!CInvokeCreateProcessVerb::_PrepareAndCallCreateProcess+0x1f0
05 windows_storage!CInvokeCreateProcessVerb::_TryCreateProcess+0x37
...
12 SHELL32!CShellExecute::_DoExecute+0xef
13 SHELL32!<lambda_256575380a6c28e7d0c1969b7475c209>::operator()+0x62
```

再看CreateProcess 的实现

+ CreateProcess

```other
BOOL __stdcall CreateProcessW(
        LPCWSTR lpApplicationName, LPWSTR lpCommandLine, ...) {
  
  return CreateProcessInternalW(
            0i64, lpApplicationName, lpCommandLine, ...);
}
```

CreateProcess 是直接调用的 InternalW 函数，这个函数的第一个参数是 hToken，表明以哪个用户的身份创建进程，所以 `CreateProcessInternalW` 又实际是 `CreateProcessAsUser` 的底层函数，基本上用户态创建进程都会经过这里

   > tips: 有些EDR/系统软件，会注入DLL 到进程，以Hook *CreateProcessInternalW* 来监控进程创建。不能说不对，但是R3 对抗程序可以手动 call 更底层的 `NtCreateUserProcess` 或 `NtCreateProcessEx` 进行绕过

### 令牌

创建进程可以传入一个 hToken 参数，也叫令牌。

操作系统的功能之一是实现对系统资源的访问控制、分级分类。linux 是直接使用帐户 uid+gid，Windows 则把身份封装成了令牌的形式。Windows NT 部分所有资源被封装成了对象 Object，包括 Token，对象上可以设置访问条件，对应的进程和线程上可以设置访问身份，加起来就能实现身份对资源的访问控制。身份从系统内置或用户登陆而来

在这个例子中，令牌与狭义的进程对象创建无关。在进程对象创建完成后，初始化进程的安全属性时，`PspInitializeProcessSecurity`进行以下步骤

1. 设置进程的访问条件

   首先令牌、进程、线程在内核下都是 NT 对象，在对象头有一个 `SecurityDescriptor` 的字段用来存放访问条件。这一步是将 hToken 中的访问条件同步到新进程

   取传入参数 hToken 指向的 `SecurityDescriptor`/DACL，DACL 中可以包含多个 ACE，每个ACE 描述指定用户或者用户组可以对这个对象做什么，ACE 由Header、ACCESS_MASK(支持的操作)、Sid(用户) 组成。这个DACL 通过 `NtSetSecurityObject` 设置到新进程和新线程

1. 设置进程新身份

   进程对象中有`Token`成员，线程对象有`ImpersonationInfo`成员，进程这个叫 PrimaryToken 主令牌，线程那个叫 ImpersonateToken 模拟令牌。主令牌就是进程访问其他资源时的默认身份，模拟令牌是当前线程从别的地方是借来的身份。这个函数中设置的是主令牌

   一个Token 里面可以包含多个 SID，可以代表一个人，也可以代表一群人。在访问对象时，内核先 `SeCaptureSubjectContext`取当前可以用来做验证的身份，通过 *PsReferenceXXXToken* 这类函数从进程、线程取出两个Token，然后 `SeAccessCheck` 以目标访问条件校验当前身份，优先使用 **模拟令牌** 进行校验

模拟令牌设计，是程序为了临时改变自己的线程权限。不同的令牌关联了不同的用户资源。同样的 API 以不同的身份调用可能得到不同的结果。在服务中，`SHGetSpecialFolderPath` 取到的路径与普通用户不一致。为了消除不一致，就需要使用`ImpersonateLoggedOnUser`改变当前线程的模拟令牌，从用户进程那边借一个普通用户身份的令牌过来。其他可用于借令牌的 API 还有 *ImpersonatePipedClient`/`RpcImpersonateClient*

   > 模拟令牌是一个灵活好用的设计，但同时也存在恶意借令牌。举个例子，xp_cmdshell 或者 webshell 的宿主 IIS/MSSQL 权限都很低，但它是服务，一般都能借令牌，这种情形下，如果能让一个高权限的进程访问它的 Pipe 或者 Rpc 接口，就能通过上面的函数拿到高权限的令牌，接着以新令牌起进程做事。详细可以参考土豆家族

随着安全问题的对抗，与对权限控制更细致的要求，Token 包含越来越多控制信息

+ 更多权限控制
   1. SACL

      如果在对象的 DACL 中为用户或组添加了ACE，那么以这个组或用户运行的进程都可以访问此对象。现在Windows 想让这些同样身份的进程区分出来，比如同样的身份，可以允许Word 进程但限制浏览器进程。为此定义了 Integrity Level 的概念，网上自动翻译完整性级别，我觉得可能叫正义级别更准确

      可以使用`RtlSetSaclSecurityDescriptor`设置Security Descriptor 中的SACL 等级。加了 Sacl 后，在用目标 DACL 检验身份前，先检查双方的 SACL，低级别访问高级别先使用SACL 的规则过滤一遍，再来匹配DACL

      SACL 中也是 ACE，其中 SID 被用来表示等级，SACL 的SID 结构中，标识部分是固定的SECURITY_MANDATORY_LABEL_AUTHORITY，域部分填 0x1000 / 0x2000 表明正义等级，Mask 可以填 `NW/R/X，`一般就是NW 不允许低级别的来写。[https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)

      正义等级初始值由 Lsa 为登陆用户创建Token 时设置，进程创建对象时，如果不填安全描述符则默认继承父进程的令牌设置

      校验过程与DACL 一样放在 `SeAccessCheck`

      - 有一个 `CreateRestrictedToken` 也是做限制。拿一个好 Token，限SACL、限关联的用户和组 SID、删 Privileges。App 沙盒功能用的多
   1. Privileges

      Windows 为用户操作规定了一套权限叫 Privilege，将每个身份能够对系统做的影响圈定在一个范围内。在关键操作的API 卡一道。比如模拟其他令牌的 API 中，检查当前线程的令牌是否包含`SeImpersonatePrivilege`，修改DACL 的时候检查`SeSecurityPrivilege。`Lsa 在创建用户Token 时赋予不同用户不同的权限列表保存在各自`TOKEN.Privileges`，在 API 调用的检查中匹配这个字段

      普通用户程序想使用未被赋予的权限，需要高权限用户`LsaAddAccountRight`。默认设置中模拟令牌只有服务程序有，修改 DACL 的权限只有管理员或`NT AUTHORITY\SYSTEM`

      校验过程放在 `SePrivilegeCheck`

   1. Process Protection Level

      这是微软官方自己出的一个进程自保护模型，其他公司也能用。可以限制其他进程对受保护进程的 RW、Impersonate、调试、消息监听等。微软在PE 签名中增加了是否受保护的配置。右键 PE → 数字签名 → View Certificate → Detail → Enhanced Key Usage。普通进程这里一般是 "Code Signing"，受保护进程这里新增了几项配置，用来定义进程自保护等级，读取到进程结构`EPROCESS.Protection.Level`，进程初始化时将 Level 转成 Sid 存放在进程主Token 的`TrustLevelSid`。ida `ntoskrnl!SepSidFromProcessProtection`看起来有 7 个级别。进程间互相访问时，按等级处理，可以高到低不能低到高，限的比较严格

      这个机制不防内核，调试或操作关键进程时，这个将这个 Level 先清零

      Token 中的 SID 校验放在`SeAccessCheckEx/SepTrustLevelCheck`，进程变量中的 Level 检查放在进程*OpenProcedure → RtlTestProtectedAccess*

      - Mitigation Policy

         也是一种增强进程自身防护的方法，可以通过组策略之类设置，算不上权限管理，但也会影响程序行为。可以用来屏蔽syscall、阻止非微软模块、禁止动态代码等

   Windows 权限控制方式比较分散而且设置的入口也分散，与linux、osx的权限管理不同。linux权限关联到帐户，比较简单清晰。正确设置 RWE 和 uid+gid 关系一般不出什么意外情况。osx 也是类似，只多加了一层限制 root 的 SIP

   这种分散造成的结果是许多开发者并不能很好的理解权限的设计，在部署产品时倾向于尽可能多的获取权限，比如Admin 运行，比如启动即获取`SeDebugPrivilege`，而在创建资源对象时又尽可能的传入低权限 SD，比如空 DACL 和SACL，这事实上降低了系统与应用的安全性，但微软自己搞这么复杂这锅至少得背一大半

令牌的东西还有很多，有几个在开发中经常会遇到的

1. 服务创建的 Event/Mutex 在主程序无法打开
2. 安装程序写的日志文件，主程序打开时报错

首先就需要考虑是不是令牌问题。因为服务通常是 System 令牌，安装程序通常是 Admin 令牌，它们默认创建的东西，其中 DACL 通常不包含普通用户。以用户权限执行的程序，可能 SACL和 DACL 都会匹配失败，打不开很正常。此时需要注意服务或者安装程序在创建对象时传入一个低权限的 SecurityDescriptor，DACL 设空或将 Users 加进去，并将SACL 设空

回到进程创建，进程创建的详细过程比较庞大

### CreateProcessInternalW

IDA 进入`kernelbase!CreateProcessInternalW`。进程可以简单看作代码的容器，先创建容器，把代码放进去，再起一条线程将代码执行起来

逻辑上首先读 lpDirectory、pEnvironment，再确认 hStdInput/hStdOutput 等，这是通用的 Windows 函数常规开头：检查参数、准备参数。在将执行环境相关的东西确认之后，从 lpApplication 或者 lpCommandLine 提取执行目标。这两个一个有值就可以，如果 Application 没有值，从 CommandLine 里面截取，如果 CommandLine 没有值，就把Application 赋给它。程序 call CreateProcess API 的时候给的主程序路径可以写相对路径，直接 cmd.exe 或 %compsec% 类似这种，这里的目标路径解析，依赖当前进程的环境变量、工作目录设置

进程的环境变量通常继承自父进程，服务与用户程序的环境变量差异较大。有时调用的 API 或网络行为在两类程序中表现差异，可以检查环境变量设置

参数准备过程中，会检查目标是否 AppContainer，是的话会创建一个权限受限的Token 并初始化相应Object 目录，AppContainer 是另一个较大的内容，从代码发展变化角度，它是想抄一下 MacOS 应用的沙箱模式，这里先略过

启动过程会检查`ImageFileExecutionOptions`，开发过程中用的比较多的是该键值下的 `Debugger` 字段，是比较经典的映像劫持位置。如果存在设置，启动过程会用 Debugger 里预定义的命令行替换原命令行

   > tips: 这个功能预期是调试特定进程使用，以前有恶意软件利用这个做驻留。
   > 调试相关还有一个设置是即时调试器， `AeDebug` 字段，有程序抛异常时调用。
   > 还有`SilenceProcessExit` 字段，设置 *MonitorProcess* 为恶意程序路径，原进程退出时会执行预定程序

通过 ida 可以看到参数检查过程中有些 *NtVdm* 的处理逻辑，*NtVdm* 开头的都是给 16 位程序运行做的一些兼容，当启动16 位程序时，实际 *ntvdm*.exe* 作为主程序运行，提供一个模拟环境。

> *if (IsBasepProcessInvalidImagePresent()) {*
   > *NtVdm64CreateProcessInternalW(... lpApplicatioinName ...*

x64 已经不支持 16位了，略过。[https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/x64-windows-not-support-16-bit-programs](https://learn.microsoft.com/en-us/troubleshoot/windows-client/application-management/x64-windows-not-support-16-bit-programs)

CreateProcessInternalW 开头生成的一部分环境设置相关的配置与属性，比如输入、输出、MitigationPolicy 会做成一个属性列表 AttributeList。目标、命令行、目录等与EXE 强关联的通过调用`BasepCreateProcessParameters` 做成一个参数块

   > tips: 参数块是 `RTL_USER_PROCESS_PARAMETERS`结构，会挂载到进程的 PEB 结构体上。PEB是用户态内存。
   > 在 win81 之前，一般用户态程序获取其他进程的命令行参数，都是从这里读。
   > win81 之后在 NtQueryInformationProcess 中提供了获取命令行功能，不过读的还是这个地方。

前面这部分可以总结为以下流程：

*CreateProcessInternalW*

   *→ Validate Parameters*

   *→ Generate Attributes List*

   *→ Get Process Image File Path*

   *→ Generate _RTL_USER_PROCESS_PARAMETERS*

   *→ NtCreateUserProcess*

   ...

+ PEB 结构体保存的 _RTL_USER_PROCESS_PARAMETERS 定义

```other
-- WRK1.2
typedef struct PEBTEB_STRUCT(_PEB) {
  ...
  PEBTEB_POINTER(PVOID) ImageBaseAddress;
  PEBTEB_POINTER(PPEB_LDR_DATA) Ldr;
  PEBTEB_POINTER(struct _RTL_USER_PROCESS_PARAMETERS*) ProcessParameters;
  ...

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ...
  CURDIR CurrentDirectory;
  UNICODE_STRING DllPath;
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
  PVOID Environment;
  ...
```

+ Win81+ Windows 提供的新查询方式

```other
-- Process Hacker
...
status = NtQueryInformationProcess(
    ProcessHandle,
    ProcessCommandLineInformation,
    buffer,
    bufferLength,
    &returnLength
    );

-- ntoskrnl
case ProcessCommandLineInformation:
  PsQueryProcessCommandLine(...)
    commandLineOffset = &peb->ProcessParameters->CommandLine;
    MmCopyVirtualMemory(outputBuffer, ...)
```

- ## 创建进程对象

参数准备完毕，转入内核。

```other
- 转到内核创建的函数定义
NTSTATUS __stdcall NtCreateUserProcess(
        PHANDLE ProcessHandle,
        PHANDLE ThreadHandle,
        ACCESS_MASK ProcessDesiredAccess,
        ACCESS_MASK ThreadDesiredAccess,
        POBJECT_ATTRIBUTES ProcessObjectAttributes,
        POBJECT_ATTRIBUTES ThreadObjectAttributes,
        ULONG ProcessFlags,
        ULONG ThreadFlags,
        PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
        PPS_CREATE_INFO CreateInfo,
        PPS_ATTRIBUTE_LIST AttributeList)
```

对比 NT4，代码流程还是变化很大。早期进程主程序文件的 Section 是在用户态创建的，把主程序的 Section 传递给 `NtCreateProcess`。现在用户态是 call `NtCreateUserProcess`，只负责传递参数与配置，其他都在内核底下完成。不过 Windows 依旧提供了 `NtCreateProcessEx`，可以支持 R3 以 Section 形式创建进程

内核创建流程总体可以分为 3 个部分

1. 将目标可执行程序创建为 Section
2. 创建进程对象，把 Section 映射进去
3. 创建线程对象，线程执行起点设置为进程初始化入口以支持用户态继续完成初始化

函数开始，Windows 使用了一个 Context 结构把R3 传递过来的参数都读进来，之后校验，检查没问题再给后续过程使用。Windows API 典型步骤，检查参数、填充局部变量、逻辑。这样一个优点内部控制逻辑不易被传入参数影响，提升代码健壮性。不过偶尔还是会有问题，[https://github.com/exploits-forsale/24h2-nt-exploit](https://github.com/exploits-forsale/24h2-nt-exploit)

开头有一些 Silo 的操作与 AppContainer 有关，与R3 类似，先略过。

```other
- PspEstimateNewProcessServerSilo
- SeQueryServerSiloToken
- PspIsSiloInSilo
```

### 创建Section

参数读入后，先使用`ntoskrnl!IoCreateFileEx` 打开主程序文件，再用 `ntoskrnl!MmCreateSection` 为文件创建 Section 对象给后续使用

> *→ driverContext = PspCreateUserProcessEcp (GUID_ECP_CREATE_USER_PROCESS, ...*
> *→ IoCreateFileEx (lpApplicationPath, ..., driverContext)*
> → *MmCreateSpecialImageSection*
> → MiCr*eateSection*

这个步骤目前发生在创建者进程中，Section 创建过程还需要校验 PE 格式，检查目标程序的有效性。Win10 之前这里是 ZwOpenFile，换 IoCreateFileEx 可以支持传递一个 Ecp

   > tips: Ecp - Extra Create Parameters 额外的创建参数，挂在 DriverContext 中，参数传递到IoCreateFileEx 后，会装进 POPEN_PACKET 的结构，在 IO 管理器构造 IRP 时，`IRP.UserBuffer` 会指向这个 Ecp 列表，所以即使处理 `STATUS_REPARSE` ，新 IRP 的其他内容都变了，这个 Ecp 也不会变，这使得 Ecp 可以标识创建请求的最初来源。
   > 还有一个类似的是 `IoSetTopLevelIrp`，它会设置当前线程的 `TopLevelIrp` 字段，也可以用来做标识，但它只有一个槽，内核与其他厂商也频繁使用，可能会影响不健壮的逻辑。
   > SMB 使用 Ecp 标识文件打开来自 SMB 服务 *GUID_ECP_SRV_OPEN*，文件过滤中也常常用它作防重入。[https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/system-defined-ecps](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/system-defined-ecps)

在内核底下，基本的功能主体都是设备，文件、网络、键盘、usb 等等。设备都是通过 IRP 来操作的，既能异步运行，又能往设备栈无限堆叠过滤层，是很经典的设计。虽然像现在出现类似 linux DPDK 去bypass 网络栈、DirectX/Vulkan bypass 图形栈这样的做法，但从设计上讲也只是一种选择而，减少层级提高性能，增加层级提高兼容与稳定

CreateFile 进入 R0 后依次经过 `Nt/Io/Ob`，然后构造 IRP，从设备栈的顶部，比如 FltMgr 文件系统过滤层，到 Ntfs/Cdfs 文件系统层，再到 Scsi/ATA 文件存储层，中途可随时完成此次操作，IofCallDriver 往下走，完成例程往回走

因为对于过滤层这块功能的开发，其实还是比较依赖对整个设备栈的了解的，很容易写出蓝屏，可能也是为了提高内核的稳定性与扩展性，微软对于许多设备模块做了封装。像对于文件封装了 minifilter，网络封装了 WFP/NDIS filter，设备上鼠标键盘封装了 KbdClass/MouClass，USB封装了USBCCGP，图形有 DXGI/Windows Graphics Capture API，摄像头DShow/AvStream 等等，虽然不同驱动模型封装隐藏的细节不同，对外提供的接口也并不统一，但设备访问的这种基础逻辑是不变的

回到文件创建，OpenFile 这个标识放在 `NtCreateUserProcess` 可以针对 Process Ghosting。

   > tips: 识别那些使用 NtCreateProcessEx 避免触发进程创建消息而逃避查杀的行为
   > 过程举例：
   1. > 加载器以 DELETE_ON_CLOSE 打开一个白文件，写入payload EXE
   2. > 加载器 map EXE 到内存，NtCreateSection
   3. > 以 Section 创建进程 NtCreateProcessEx，这里不会触发进程回调
   4. > 关闭文件句柄，因为 DELETE_ON_CLOSE，文件会被删除，或者这一步用事件回滚白文件
   5. > NtCreateThreadEx 创建线程，这里会触发进程回调，但是杀软找不到恶意文件了
   > 对抗部分，安全软件可以在第 2步 PostCreate 确认创建动作是否带 *GUID_ECP_CREATE_USER_PROCESS*，在第 5步进程创建回调中查看进程对应 FileObject 是否有这个标记，没有的就是在尝试逃避扫描的

继续向前，主程序打开后，使用文件句柄调用 `MmCreateSection`

+ SECTION 对象

```other
- WRK
typedef struct _SECTION {
    MMADDRESS_NODE Address;
    PSEGMENT Segment;
    LARGE_INTEGER SizeOfSection;
    union {
        ULONG LongFlags;
        MMSECTION_FLAGS Flags;
    } u;
    MM_PROTECTION_MASK InitialPageProtection;
} SECTION, *PSECTION;
```

Section 是一个很好的设计，它让系统所有进程能安全的共享同一份文件内存，而且没实际使用的内容不加载到内存中，减少了巨大的内存消耗，又提升了性能。

Section 创建过程中，先读 PE Header 文件头，这个要实时读取，整个创建过程，实时读取文件内容的次数非常少。接着解析PE 头，格式不对的直接退出。

继续解析PE 中的节，取节大小，根据预定义的对齐数，先算一下要占多少页物理内存，再用一个 `SEGMENT` 对象申明要用到 X 页物理内存，可以理解为动态分配了一个数组，数组存放指向物理内存的PTE 指针。为了节省内存，物理内存现在是不分配的，这些 PTE 初始化时会设置 Prototype 位，表明是个半成品，暂时不指向有效的物理页。

接下来要创建一个管理结构 `CONTROL_AREA`，里面定义了比如有几个节、目前自己被引用了几次、Section 内容来源、关联的文件对象等，`CONTROL_AREA` 后面紧跟 Subsection 数组，每个对应 PE 的一个节，如果是 Page File / Data File 就只有一个节。

Subsection 中定义了节在文件中的偏移，读文件内容时使用；定义了保护属性，可读、可写之类；申明了当前这个 Subsection 要用 SEGMENT 中第 X 页到 第 Y 页的内存。

SEGMENT 的内存数组，都是给 Subsection 用的，各自被初始化为使用它们的 Subsection 的地址。当发生缺页时，内核可以从这个发生异常的地址找 Subsection 和 Subsection 的头 ControlArea，ControlArea 中有内容来源、文件指针，Subsection 中有文件偏移，加起来就能把文件内容读出来。

上述内存结构弄完，创建一个包装它们的 Section 对象。把 SEGMENT 包进来。再设置创建时的访问属性、PE Image 内存占用大小。虽然目前几乎还没有内容加载到物理内存，但这个 Section 已经可以拿出去使用了。

+ 主要结构体之间的关系

![Image.png](https://res.craft.do/user/full/e0ddc5a5-b773-2a5d-9c6c-c8948f3f54b3/doc/B9C47814-7BC7-433F-804D-5F9706AD909E/82027906-618B-472D-8667-1D3E3B2E1791_2/tkt2xdgRxbzfYvPY9wYZkueDcyKxcfAkymY3M3kaA3Ez/Image.png)

当然，既然说 Section 可以节省大量内存，不单单只是懒加载的设计。

`MmCreateSection` 开始时，会检查传入参数，目标文件 FileObject，如果 FileObject 有值，且 `FileObject->SectionObjectPointer->ImageSectionObject` 有值，这个成员就是一个 ControlArea。剩下就简单，直接复用。

创建一个 Section 对象，Segment 用已有的，给已有的 ControlArea 加引用计数，创建就算完成了。在文件过滤驱动中处理 Section 对象时需要注意 Section 可以共享这点，不要多次创建产生冲突

打开任务管理器，转到“Details”，可以看到进程私有占用的物理内存是比较少的，大多都是共享，依托的就是Section

+ 任务管理器视图

![Image.png](https://res.craft.do/user/full/e0ddc5a5-b773-2a5d-9c6c-c8948f3f54b3/doc/B9C47814-7BC7-433F-804D-5F9706AD909E/D706804D-FB07-49BF-8348-7AE46D3EB195_2/kVcSwwGC67wLwi56xkx84CAAWxN8t0oowxZnY6FFMh8z/Image.png)

Section 创建出来后，仅代表内存结构已经建立，想要在进程中通过指针访问文件内容，还需要将它映射到进程中

当下的例子，这个可执行文件的 Section 要等新进程初始化完自己的虚拟内存空间，才能被 `MmMapViewOfSectionEx` 挂上去，放后面说。

   > tips: 在 PE 类型的 `MiMapViewOfImageSection` 执行尾部，有一个熟悉的回调，ntoskrnl!`PsCallImageNotifyRoutines`，是 DLL/驱动 加载的通知。这里有一个经典问题，有些人尝试在这里做注入或修改 DLL 内容，在调用 Query/Protect/Alloc VirtualMemory 之类的操作时，发现进程卡死了。
   > 这是因为`MmMapViewOfSection`正在操作 VadRoot，会把对 Vad 的操作锁起来。
   > 这个位置是不合适的。
   > `- WRK MmMapViewOfSection`
   > `// Get the address creation mutex to block multiple threads`
   > `// creating or deleting address space at the same time.`
   > `//`
   > `LOCK_ADDRESS_SPACE (Process);`
   > `→KeAcquireGuardedMutex (&((PROCESS)->AddressCreationLock))`
   > `MiMapViewOfXXX ...`
   > `UNLOCK_ADDRESS_SPACE (Process);`

经过上面的步骤，我们可以实现共享文件的内存，但是要安全的共享，还需要`Copy-On-Write`。

一般 Section 映射到进程中，Vad 属性会设置为 `MM_EXECUTE_WRITECOPY`。这个标志表明：当进程对此 Section 做写入操作时，系统将原物理页复制出一份新的，然后新建或合并自己进程的 MMVAD，将指向原物理页的虚拟地址改为指向新物理页，这样修改被限定在了当前进程中，同时产生一块新的 Private 内存。处理逻辑见 `ntoskrnl!MiCopyOnWrite`。

我们在R3 使用的 `CreateFileMapping`，底层是 `NtCreateSection`，后续的 `MapViewOfSection` 也对应底层 MapView。这是 Windows R3 文件编程通用做法，性能和内存消耗都比较小

> **❓缺页**
> 上面的节省内存和Copy On Write 都依赖缺页。缺页是 Windows 异常处理的一部分，CPU 根据它可能产生的访问异常，提供了一个 IDT 表，给操作系统填处理函数，初始的处理项见 `ntoskrnl!KiInterruptInitTable`，类似 VT 的 *ExitHandler*。简而言之，就是操作系统告诉 Cpu：“碰到 xxx 的意外情况，跳到 yyy 的地方处理”。
> Windows 11 处理页异常的函数是 `ntoskrnl!KiPageFault`。它会尽可能的恢复缺失的内容，像前边的 Prototype 位的 PTE，或是后边映射过后的 Section。访问异常发生时，去分配物理页读真正的内容。
> 内存管理的 Page Fault 机制，也很广泛的用在 VT-x/SVM 上。对相同的物理地址，给不同进程以不同的页面，作为实现无痕 Hook，bypass PG 等的其中一种方式。

成功创建Section 之后，将文件句柄、Section 句柄、文件对象等都存放在 Context 中，下一步，就该是创建进程对象了

### 页表

在继续之前，不得不先讨论下页表的内容，进程初始化与内存使用都绕不开，这是现代操作系统内存管理的基础机制。性能与效率考虑，现代操作系统的页表有点复杂。

对于内存管理来说，假设第一代操作系统只能运行一个进程，那么直接操作物理内存即可，不需要转换，指针随便指，不越界就行。放到现在就是实地址模式，不过如今可能只有 BIOS、grub、boot loader初期 这类独占整机资源的程序还在使用。

![Image.png](https://res.craft.do/user/full/e0ddc5a5-b773-2a5d-9c6c-c8948f3f54b3/doc/B9C47814-7BC7-433F-804D-5F9706AD909E/4CBE2D31-64C9-49D0-A172-85F56F305B2B_2/BTxEn1XMMyrggSHqDByeukPnw4dddpXfsMp5PfoNUBUz/Image.png)

当需要运行多个进程的时候，必须引入虚拟地址。任意进程都能访问同一个地址，进程内将此地址映射到不同的物理内存上去。否则实地址下，为了不串数据，开发者要分别记住所有程序用的物理内存地址范围。

要把虚拟地址映射物理地址的关系记下来，就需要每个进程有一张表，Cpu 访问内存时来查表。

如果现在是一个32 位的环境，内存有4G，假如每个 4字节的物理地址都对应进程中的一个 4字节虚拟地址，映射完 1 个进程后内存刚好用完。

所以不能每个地址都对应，对应一部分，剩下的部分虚拟地址和物理地址保持一致。

比如一个虚拟地址为 0x00001555。

- 把前边 0x00001 对应到物理地址上，假如是 0x000FA
- 后边的0x555 直接用，最终物理地址 0x000FA555
- 其他进程可以把 0x00001 对应到 0x000FB上
- 后边的0x555 直接用，最终物理地址 0x000FB555

这极大的减少了需要映射的地址数量。但这样做缺点是物理内存每次得给一片 0xFFF 大小，要想映射的条目更少，就需要每次给的内存片更大，要想每次给的片小，映射条目就要增多。

现代操作系统一般定义 4K 的连续空间为 1页，做一个基本的内存管理单元，这样地址中有 12 个位不参与映射。

![Image.png](https://res.craft.do/user/full/e0ddc5a5-b773-2a5d-9c6c-c8948f3f54b3/doc/B9C47814-7BC7-433F-804D-5F9706AD909E/65C095DD-2F04-458B-8F33-77BEF6ED58B6_2/bx8sLmkDzyfKmuNJuG29jhAQfEnuOTRzDfTnTyIZZQIz/Image.png)

重新算映射表的内存占用，4G 物理内存现在相当于需要管理0x100000 页，每个地址4 字节，共占用 4M，运行100 个进程要用 400M，还是有点多。继续优化。

现在所有物理内存都按页管理了，映射表现在也改用页管理，一个映射页可以放 1024项映射，每个映射指向 1个 4K页，总共 1 个映射页可以索引 4M 的内存，总共 1024 个映射页可以索引 4G 的内存。

现在空放着什么都不干进程索引 4GB 需要 4M，那假如进程里面只用到了一小部分虚拟地址呢，假如进程只用到了 0x00001000 到 0x00005000 的地址范围，那其实只需要 1 个表页占用 4K就行，1 个表页有 1024 项能索引 0x000000 到 0x3FF000。跟 Page Fault 结合起来，表页等访问异常了再初始化，不用了就释放，这样就能节省大量空间。

这样做的缺点是不能保证整个映射表的连续性。比如上面计算的1024个表页平坦的排在内存中，数组大小 1024*1024，只要有个基址就能找到对应的物理页。比如 0x00001000 就找 Array[1]，0x00300000 就找 Array[0x300]。

现在既然不连续，就需要有一个连续的数据，把不连续的部分关联起来。

回到 4G 空间，上面算过需要 1024个表页，那可以做一个数组，放1024 个指针，指针指向表页，先全部填0。访问地址的时候，比如 0x7F000200，把 0x7F000 拿出来，除以 1024，其实就是右移 10 位，得到508。此时再给 508 的指针分配一页内存，再继续访问。

这样更灵活，内存消耗也更少。而且地址中还有12 个bit 没用上的，把内存页的访问属性加上去。

这构成了经典的32 位下 10-10-12 地址模式。第一个10 可以表示 1024项指针数组的索引，叫 PD - Page Directory，子项叫 PDE，第二个 10 可以表示 1024 项表页的索引，叫 PT - Page Table，子项叫 PTE，后面12 位直接用，可以叫 Offset。

![Image.png](https://res.craft.do/user/full/e0ddc5a5-b773-2a5d-9c6c-c8948f3f54b3/doc/B9C47814-7BC7-433F-804D-5F9706AD909E/90402FE9-46DA-47FE-9B1D-0CD23602129A_2/op0K4lZgRCtxjYhig6bZ9XHL6K2SyzWLYAuxtWiMJfIz/Image.png)

这个结构在64 位之前比较稳定。

64位理论可以支持的地址空间高达1600多万TB，这种情况下，不能继续沿用 PD和PT，PD才1024 的大小，最多支持 4G，除非改页的大小，但页改大了就很容易浪费内存，而且操作系统代码得有一场大改。这种情形，势必要给地址再加点层级。

64bit 继续沿用 4K 的页，依然用 12 位Offset，这导致页表现在放不下 1024 个项，32 位时 4字节一个物理地址，现在得 8字节一个物理地址，所以1 个页表目前只有 512 项，管理 2M 内存。同样的道理，页目录也只有 512 项，刚好管理 1个G。只要页大小不变，往上加的层级都只有 512 项。512项的索引，占9 个bit。

PD能管 1G，按现实条件来说，往上再加一个表，能管理 512G，看着也挺足够大家用了，不过 x64 往上再加了一级，算下来能管理 256TB 的内存，这下真的绰绰有余了。以这个反推，物理地址索引 256TB 也不需要用到所有 64 个位，只需要用到 48 个位。

这就构成了 9-9-9-9-12 的 x64 内存地址结构，实际用 48位。最前边的就叫 PML4，第二叫 PDPT，后边 2个保持不变。

但也有缺点，因为现在层级变多，一页能管理的内存变少，导致CPU TLB 高速缓存命中率下降，CPU 会存储最近常用的虚拟页号和物理页号的对应关系到内置的TLB 缓存中，以减少访问主存。访问缓存是 Cpu 内部操作，比访问主存快几百倍。而内置缓存增加会导致CPU 复杂性增加、能耗增加、切任务时缓存保存、还原成本等问题。

所以TLB 条目基本不会变，在这种情况下，操作系统就推出了大页的概念。页大了，操作的页不就少了吗，TLB 记录不就少了。

大页从页表实现来说无非就是减少层级，这个减少可以做的很灵活，以PT 为例，子项保存的指针是64位的，用了48位，还有很多位可以用来设置属性，其中一个属性叫 Present，表示到头了这就是物理地址，这种情况下，我直接给 PD 设置 Present，PD 当一个页使，能用来索引的变成 21位，2的21 次方可以管理 2M 的页。如果把这个标记放到 PDPT 中，2 的30 次方可以管理 1GB 的页，更大没必要，39位可以索引 512GB。

![Image.png](https://res.craft.do/user/full/e0ddc5a5-b773-2a5d-9c6c-c8948f3f54b3/doc/B9C47814-7BC7-433F-804D-5F9706AD909E/663B6424-7416-44D2-AE08-F4A3BC5B9D62_2/BN4Bxtiyh6yU9bJ6e4QSwPW3Uw8NiCH0YOdiPJdbx1Iz/Image.png)

页表粗略的概念就是这样了，接下来继续进程的创建。创建初始就需要创建自己的页表

### PspAllocateProcess

进程可以看作是一个容器，里面存放了各类资源，进程对象，就是访问这个容器的索引。内核态与用户态的进程创建，都会走到 `PspAllocateProcess`

Allocate 开头需要通过 `ObCreateObject` 创建一个进程对象 `EPROCESS`。`EPROCESS` 结构非常大，摘抄一部分。

+ EPROCESS

```other
typedef struct _EPROCESS {
  +0x0000 struct _KPROCESS Pcb;
  ...
  +0x0440 void* UniqueProcessId;
  +0x0448 struct _LIST_ENTRY ActiveProcessLinks;
  ...
  +0x04a0 struct _LIST_ENTRY SessionProcessLinks;
  ...
  +0x04b8 struct _EX_FAST_REF Token;
  ...
  +0x0508 void* Win32Process;
  +0x0510 struct _EJOB* volatile Job;
  +0x0518 void* SectionObject;
  ...
  +0x0540 void* InheritedFromUniqueProcessId;
  ...
  +0x0550 struct _PEB* Peb;
  ...
  +0x0598 unsigned __int64 PageDirectoryPte;
  +0x05a0 struct _FILE_OBJECT* ImageFilePointer;
  +0x05a8 unsigned char ImageFileName[15];
  ...
  +0x07d4 long ExitStatus;
  +0x07d8 struct _RTL_AVL_TREE VadRoot;
  ...
  +0x087a struct _PS_PROTECTION Protection;
  ...
  +0x0b70 unsigned long DisallowFsctlSystemCalls : 1; +bit position: 1 */
  +0x0b70 unsigned long AuditDisallowFsctlSystemCalls : 1; +bit position: 2 */
  +0x0b70 unsigned long MitigationFlags3Spare : 29; +bit position: 3 */
  ...
} EPROCESS, *PEPROCESS; +size: 0x0b80
```

Windows NT 内核的资源都是对象管理的，文件、注册表、进程、线程等等。

对象有统一规范，先要在系统中注册对象类型 `OBJECT_TYPE`，其次需要使用 `ObCreateObject/Ex` 创建，不要自己Alloc。Windows 需要给创建出来的对象加管理结构`OBJECT_HEADER`。内核代码会使用 `OBJECT_TO_OBJECT_HEADER` 定位对象头，这个宏是个 `CONTAINING_RECORD` 往前找偏移

已注册的对象类型可以通过 `Sysinternals/WinObj64.exe->\ObjectTypes` 查看

对象类型中定义了 `INITIALIZER`，其中有定义了对象的增删改查函数指针，在没有 PG 保护时，这里一般都会被 Hook

+ OBJECT_TYPE_INITIALIZER

```other
typedef struct _OBJECT_TYPE_INITIALIZER {
  +00 unsigned short Length;
  +02 unsigned short ObjectTypeFlags;
      // SupportsObjectCallbacks
  +04 unsigned long ObjectTypeCode;
  ...
  +30 void* DumpProcedure;
  +38 void* OpenProcedure;
  +40 void* CloseProcedure;
  +48 void* DeleteProcedure;
  +50 void* ParseProcedure;
  +58 void* SecurityProcedure;
  +60 void* QueryNameProcedure;
  +68 void* OkayToCloseProcedure;
  ...
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER; /* size: 0x0078
```

> **对象回调**
> Windows 提供的内核 API 接口不支持对象本身的过滤操作，只提供过滤对象句柄功能，就像 OpenProcess，过滤的不是访问进程的操作，而是生成进程句柄的操作。`ObRegisterCallbacks` 支持 进程、线程、桌面的句柄
> 这个回调目前最大的作用就是进程自保护了。当其进程尝试使用 `OpenProcess` 时，会触发回调，回调中可以拒绝或修改权限
> 但是不防内核，内核驱动一方面它的执行环境本就在目标进程上下文，其二可以不用 Handle 直接使用进程对象，也可以 KeAttach
> 微软为了支持句柄过滤，在对象类型中增加了`OBJECT_TYPE.CallbackList` 字段，当通过 `ObRegisterCallbacks` 注册回调时，事实是把用户回调挂在这个链表上。
> 操作对象时，比如 `OpenProcess`，内核先 `PsLookupProcessByProcessId` 获取 EPROCESS，然后 `ObpCreateHandle` 为操作进程分配 Handle，系统回调 `ObpCallxxxOperationCallbacks` 就在这个函数中触发。Duplicate 在 `ObDuplicateObject`时触发。
> `ObRegisterCallbacks`会判断对象类型中的 `TypeInfo.ObjectTypeFlags.SupportsObjectCallbacks`，值不为 0 才允许挂。我们可以自己实现ObRegister 绕过这个检查，但是句柄操作函数也检查此标记。也不能改这个标记，会PG。

继续进程的创建，进程对象创建出来，接着初始化对象的内部成员。

成员中需要特别关注：

1. `"EPROCESS.Pcb.DirectoryTableBase"`这是进程页表的物理基址，就是 PML4 起始位置的物理页号，CPU运行时，取到的进程虚拟地址都要经过对页表的查表得到物理地址。进程切换的时候，内核 CR3 取这个值。

   除了有 `DirectoryTableBase`，还有 `UserDirectoryTableBase`。一个进程，按之前的讨论，一个页表就够了。这里用了两个页表，是为了解决之前的 Meltdown 用户态程序可以任意读内核数据的问题。

2. `"EPROCESS.VadRoot"`这是一颗 AVL 树，记录了属于当前进程的虚拟地址，进程 VirtualAlloc 出来的，包括堆和文件映射的内存，主要是用户空间，内核内存的虚拟地址像 ExAllocatePool 有内核虚拟地址管理的方法。

   每个VadRoot 的项都是一个MMVAD，定义了保护属性、地址、大小、是否空闲等。所有call 到 `Nt...Virtual.../Virtual...` 的API 都会操作 Vad。

   + MMVAD

```other
typedef struct _MMVAD_SHORT {
  +00 struct _RTL_BALANCED_NODE VadNode;
  ...
  +18 unsigned long StartingVpn;
  +1c unsigned long EndingVpn;
  +20 unsigned char StartingVpnHigh;
  +21 unsigned char EndingVpnHigh;
  ...
  +30 struct _MMVAD_FLAGS VadFlags;
  ...
} MMVAD_SHORT, *PMMVAD_SHORT; size: 0x0040

typedef struct _MMVAD {
  +00 struct _MMVAD_SHORT Core;
  +40 volatile struct _MMVAD_FLAGS2 VadFlags2;
  ...
  +60 struct _LIST_ENTRY ViewLinks;
  +70 struct _EPROCESS* VadsProcess;
  ...
  +80 struct _FILE_OBJECT* FileObject;
} MMVAD, *PMMVAD;  size: 0x0088
```

   > tips: 通过 Windows API 对进程的内存操作都要经过 Vad，访问不在 Vad 中的地址或权限不匹配会访问异常。像 NtQueryVirtualMemory 函数，这个函数常用来查找进程中的隐藏模块，它的底层就是遍历 Vad，所以也有一些将内存从 VadRoot 断开的思路用以隐藏内存

3. `"EPROCESS.Peb"`存放了大多数进程逻辑与内容相关的信息。Peb 因为对于R3 影响比较多，内容也比较动态，一般不会 PG，这里被修改的比较多。

### → MmCreateProcessAddressSpace

进程对象如果是索引，地址空间就是进程的容器。`MmCreateProcessAddressSpace`是`PspAllocateProcess` 中最主要的2 个函数之一，功能就是把两个页表创建出来

以当前 22H2 为例：

1. 创建用户页表。`MiAllocateTopLevelPage` 创建 User 页表，页表物理页号给 `EPROCESS.Pcb.UserDirectoryTableBase`，也就是 User CR3。页表虚拟地址给 `EPROCESS.Vm.Shared.ShadowMapping`，后续内核从这里操作用户页表。
2. 创建内核页表，同步高位 256项。`MiAllocateTopLevelPage` 创建内核页表，然后`MiCopyTopLevelMappings` 从 System 进程同步内核部分进来。

   将 System 页表内核部分，就是高位 256项，复制到进程内核页表，相当于保持所有进程页表内核部分一致。函数退出前会释放`MiAllocateTopLevelPage` 生成的 Va，修改页表中的自引用记录指向本进程的 Kernel CR3。内核操作页表时总是将目标页表映射到 HyperSpace，这样Map 的地址不会跟当前页表内容冲突。

```other
- 修改自引用的这一条
*(_QWORD *)((kcr3_Va << 25 >> 16) + 0xF68) = kcr3_Ppfn;
- 完成后将 MiReservePtes 拿到的 Va 释放
MiReleasePtes(&MiState.Vs.SystemPteInfo.LowestBitEverAllocated, kcr3_Va, 1i64);
```

3. 同步用户页表。使用`MiShadowTopLevelPxes` 填充一部分用户页表，这部分主要是取 System 进程的 `Vm.Shared.ShadowMapping` 写入新进程 Mapping。
   1. System 的 Mapping 在系统启动过程初始化控制结构时由 `KiShadowProcessorAllocation` 填充。里面主要是 `ntoskrnl[.KVASCODE]` 节的内容，ida 可定位到这一节

      主要 `KiSystemCallXXShadow / KiXXXShadow / XXXInterruptShadow` 等等这些 R3/R0 交互的代码段，因为真实的 SystemCall 不映射，这些 Shadow 代码就负责切换 CR3、堆栈，映射出去当个跳板用

   1. 还有 `ntoskrnl!KUSER_SHARED_DATA`，记录一些调试状态、系统版本之类的信息。
   2. 这部分页表的内容主要保证每个进程的用户态、内核态正常交互，而其他内存不再映射。
1. 同步内核表页低 256项
   1. 内核代码中分配一块内存，比如 NtAllocVirtual，分配成功更新内核页表，同时判断虚拟地址是否在低256 项，如果是则打上`.User` 的标记，然后 `MiWritePteShadow` 写入该条记录到`Vm.Shared.ShadowMapping` 中。上面有说这个 Map 实际是 User CR3 的虚拟地址，这样用户态就能访问这个地址了，本身内核不直接操作用户页表，都是同步
   2. 所以正常情况下内核页表的低 256 项没什么需要初始化，不过用户态还有一个 Session 相关的内容，代表用户会话，不同用户会话之间模块、窗口等隔离，同个会话间共享，进程所属Session 有一个单独的页表，负责记录会话内共享的内存，比如很关键的 win32k 与R3 交互的 `win32k!ghSectionShared`、远程桌面的内存和 DLL Section等，所以新进程初始化时，也需要拷贝这些用户态可共享访问的内容到内核页表，然后写到 `Vm.Shared.ShadowMapping`

经过上面的步骤，两个页表的高低 256 项都填充好了。其中内核页表包含进程的所有页表项，用户页表包含跳板以及会话存储的部分

### → 页表隔离与Meltdown

应用两个页表之前，系统防止用户态代码读取内核数据主要通过 GDT。GDT给不同区段的内存划分了 DPL 特权级别，R0123。对应的，进程执行环境中 cs 寄存器设置了当前访问级别 CPL R0123。cpl 是 CPU 执行到了某个指令内部自动设置的，比如 syscall/sysret/iret，不能手动更改 cs 寄存器。这种情况下，隔离用户态对内核内存访问，通过比较当前 Cpu CPL 和目的地址的 DPL 已足够。比如当前Cpu CPL 为 R3，访问目的地址 DPL 为 R0，判断访问失败

Meltdown 利用了CPU 叫做乱序执行的优化技术。在用户态访问内核数据时，权限检查会耗费一些时间，如果要等检查完再往下执行，就会浪费Cpu Cycle。所以在检查访问权限之前，cpu 会假设读成功和读失败两种情况，把权限检查、检查成功后、检查失败后 3条逻辑同时执行，等访问权限检查结束，直接对接成功或失败的运行结果，大大提高效率

此时我们可以写一段假设的代码，让CPU 乱序执行去跑，乱序执行的逻辑失败后回收状态时不会刷新CPU 缓存，这是事情的关键，我们可以通过访问缓存的速度差别去猜代码执行结果

```other
伪代码，现在 cs.CPL=3

for (i = 0; i < 255; ++i)
    trapbase[i] = VirtualAlloc(PAGE_SIZE, ...) // 分配 256 页内存，1页4K
    memset(trapbase[i], 'A' + i)
...
mov al, byte ptr [R0 Address] // 直接访问内核地址，这必定失败的
mov eax, dword ptr [trapbase + al * 8] // 乱序执行中一定有一页被CPU 缓存了
...
乱序执行中，一定有一页被访问并被缓存，虽然我不知道是哪一页，但可以通过计算访问速度找出来。
判断访问每一页的时间，时间短的就是那个被缓存过的页，页号就是 al 的值。
rdtsc 返回时钟周期，缓存是否命中性能差百倍
后续就 R0 Address 那边一个字节一个字节的读，最终把内容拼出来
```

Windows 使用两个页表的方式阻止这类型攻击，根据前边分配进程空间的逻辑，页表隔离后，用户态页表中没有内核的地址，Meltdown 的乱序执行中，假设成功的那段代码会失败。

两个表固然隔离彻底，但是会造成性能损失。比如 syscall、中断，每次从R3 进入内核，要重新设置CR3，刷新 CPU 的缓存，从R0 回到 R3 ，需要重新再做一遍，影响性能。

```other
- 是否有隔离是全局的，是否开启隔离是动态的，每个进程可以使用不同设置
BOOL __stdcall MiPteHasShadow()  {
  // 系统全局设置 MiFlags = KiKvaShadowMode << 21
  if ( (MiFlags & 0x600000) != 0 )
    // 每个进程可以单独设置 AddressPolicy
    return KeGetCurrentThread()->ApcState.Process->AddressPolicy != 1;
  return 0;
```

### → 虚拟地址划分

进程的页表可以表示所有虚拟地址，上面操作页表时高位 256 与低位 256 对待的方式不同，是因为操作系统将虚拟地址划分为了不同的用途。

在 Windows 1903 之前，内核部分的虚拟地址范围为固定划分。更早以前，用户态NTDLL 的加载地址都是固定的。随着内存安全的发展，DLL 等用户态内存早已随机 ASLR，内核地址现在也很少固定地址了。按照 WRK 的定义，这些固定的虚拟地址目前只有系统进程的 PXE，也就是 PML4 还是固定的，其他都是动态生成。

```other
#define PXE_BASE          0xFFFFF6FB7D BED 000 // PML4
#define PXE_SELFMAP       0xFFFFF6FB7D BED F68 // 第 0x1ED 项，自引用
#define PPE_BASE          0xFFFFF6FB7D A00 000 // PDP
#define PDE_BASE          0xFFFFF6FB40 000 000 // PD
#define PTE_BASE          0xFFFFF68000 000 000 // PT

- Win11 22H2，判断是否在用户页表地址范围
_BOOL8 __fastcall MiPteInShadowRange(ULONG_PTR PteVa) {
  // 7F8 即第 256 项，PteVa 范围在 0-256项之间
  return PteVa >= 0xFFFFF6FB7DBED000ui64 && PteVa <= 0xFFFFF6FB7DBED7F8ui64;
}
```

粗略探讨操作系统如何将一个虚拟地址给到程序

**物理内存变成物理页号**

操作系统启动时，经过 BIOS 引导拉起 bootmgr，在 bootmgr 中确认系统参数配置，包括物理内存大小，这里是一个内存容量总数。之后winload 把物理内存大小右移12 位，就是按 4K 页划分，得出总共有多少个物理 4K页，它的下标（0 → 页数量） 就是物理内存范围了

用 `MmPfnDatabase` 这个连续的指针数组，记录所有物理页的状态 `MMPFN`。物理地址就是物理页的下标，左移12 位，低位给页属性，比较粗放，但反正Cpu 能明白去哪读写就行。对应 *MmPfnDatabase[ 页索引 ] 的条目，记录内存使用状态

**虚拟地址**

将上一步的物理地址写到不同进程页表的某处，就得到进程可用的虚拟地址

Windows 对各类组件使用的虚拟地址范围做了划分。首先是分成内核空间与用户态空间。用户空间比较简单，先单看内核，Windows 1903 之前内核模块各区段地址固定。[https://codemachine.com/articles/x64_kernel_virtual_address_space_layout.html](https://codemachine.com/articles/x64_kernel_virtual_address_space_layout.html)

![Image.png](https://res.craft.do/user/full/e0ddc5a5-b773-2a5d-9c6c-c8948f3f54b3/doc/B9C47814-7BC7-433F-804D-5F9706AD909E/90F99BCD-53C2-4426-8A03-7E02002DDF48_2/5oiLT3W1Ta4cexi9clniAvG3mPs16k6P7miR3h37hoEz/Image.png)

1903 之后这些固定地址会被重置为随机值，从系统开机到 `MmInitSystem` 之前，还是沿用硬编码，但之后就通过调用 `MiInitializeSystemVa`用随机数重新设置各区段的基址，已加载的驱动 Relocation 一次，新加的区段 `MiInitializeDynamicVa` 随机值初始化。

为此 Windows 新建了一个`(_MI_SYSTEM_INFORMATION)ntoskrnl!MiState`的全局变量来描述所有类型内存的虚拟地址范围，之前硬编码的地址和内存相关全局变量做成 `MiState` 中的成员，通过枚举类型 `MiSystemVaType` 去 `MiState.Vs.SystemVaRegions` 中定位内存区段。

现在内核分配一块内存，先看属于什么区段，比如 Session Space / NonPaged Pool，拿到对应分配头 Bitmap，根据 Bitmap 使用情况分配 Va。这些 Va 在分配时跟物理页绑在一起，要用的 Va 的页表项如果是空，或者这个 Bitmap 已经无空闲，分配时通过 `MiExpandPtes` 初始化这个 Va 地址所在那一页的 PT，再给 Va 对应的那条 PTE 写上物理页号。

分配和释放的操作封装两个函数 `MiObtainSystemVa/MiReturnSystemVa`

**优化内存分配的速度**

主要是物理页号相关，比如找空闲页，总不能循环遍历 `MmPfnDatabase` 查看是否占用。所以在 db 的基础上，创建了多个链表 `MI_PARTITION.PageLists`，空闲链表、大页链表、数据已修改链表、活跃数据链表等，所有内存页根据自身的使用状态挂在某个链表上。链表再搞个 AVL 树、LRU之类的，就不再操作 db 了，效率就提上来了。

相应的还有一些工作线程配合，比如将修改过的内存页写回Section的、数据需要清零的、内存页要换到硬盘或换回的等等。

上边页表有说用 TLB 缓存，Cpu 内部还有关联到 Core的 L1 和L2，还有L3。这些缓存的速度比内存快多了。Windows 想利用这个缓存。于是整了一套 Color Page List。Cpu 有几个核心，就有几种 Color，Cpu 单核心L2 有多大，单个Color List 就可以做多大。Color List 通过内存清零的工作线程往Color List 里加 PTE，只放空闲的和已经清零的。

分配内存时，先检查当前核心 L2绑的内存页是否超出L2 总数`KPCR->FreeCount`，不超过Cache 总数就可以继续访问绑定在当前核心的内存页 `_MI_PARTION.PageLists.FreePageByColor`，从这里面拿的内存页，因为关联L2 缓存，访问就会很快。使用L2 的好处这里加速了内存分配，其次在当前Cpu 分配的内存大概率还是在当前 Cpu 访问，间接提升了后续内存访问速度。

内核中很多这种极尽可能的性能压榨，每次提升一点点，加起来就很多了

**PARTITION**

Windows 10 在内存管理中间加了一层`MI_PARTITION`，封装了之前的全局内存管理功能。现在可以创建多个独立的内存管理模块。

默认情况下系统只创一个 `MiSystemPartition`，可以用到系统所有内存。默认进程使用的就是这个，当然单独某个进程具体能用多少内存，还受限于 `MaximumWorkingSet` 的设置。

程序可以手动创建 `NtCreatePartition`，并分配一定的物理内存，通过 `NtSetInformationJobObject/PspSetJobMemoryPartition` 将 Job 关联到到 Partition。以此，Job 上挂的进程都将使用这个特定Partition 提供内存，每个 Partition 都有独立的工作线程、db、各种链表以及自己的 pagefile。

这个操作很适合虚拟机内存管理的场景，还可以动态调整Partition 占用db 大小

**虚拟内存**

内存紧张的时候把部分内存数据写到硬盘上腾点空间。这里出现 WorkingSet 的概念，指物理内存加上虚拟内存，表示本机能使用的最大内存量。

进程分配的 PagedPool 内存，会记录在 Partition 的 `WorkingSetLists` 中，再根据使用者不同挂到 `(PMMSUPORT_FULL)EPROCESS.Vm` 里面，系统内核使用的由 `MiState.Vs.SystemWs`结构体管理。前面说到页表与Section 的时候，讲很多数据结构只是一个声明，往往等到访问才使用物理内存，而 WorkingSet 就是记录物理内存的，包括被换到硬盘的虚拟物理内存。

进程内存空间创建结尾处以及系统初始化的时候，进程的`EPROCESS.Vm`和系统相关 WS 会默认挂上 Partition 中的虚拟内存待交换列表`_MI_PARTITION.WorkingSetExpansionHead`。

每个Partition 都有工作线程不停的在平衡内存的占用 `ntoskrnl!MiWorkingSetManager`。这条线程可以按时按需触发检查。当 Partition 空闲链表的数量小，证明内存紧张，需要换一些内容到硬盘。当Page Fault 事件变多，证明某些内存应该换回。

交换，就是遍历 Expansion 链表，根据访问频次之类的条件，将频次不高的 WorkingSet 对应的 PTE 挪到硬盘上。交换是以“集合”为索引，比如某块内核内存区域、某个进程，每次交换的数量可能不会很大，属于是频繁触发的事件。

交换的过程，沿用内存修改的那套逻辑，模拟一部分 PTE 被修改，写上关联 PageFile 字段，然后正常挂到已修改链表，后台线程会把内容写到关联的 Paging File 里面。在 Partition 初始化的时候`MiCreatePagingFile`会创建相应的页面文件，然后也按 4K 给它分，也用 Bitmap 管理空闲项，封装成一个 `_MMPAGING_FILE`。挂上已修改链的内存页写之前，修改 `PTE.u.Soft.PageFileHigh`为 Paging File 给的页号，`PageFileLow` 为页面文件ID。之后工作线程写完，物理内存就可以释放了。如果到时候又要用到这块内存，就走正常的`PageFault`。

新建进程地址空间就差不多这样，继续回到后续的初始化中

进程创建中，地址空间创建后，`PspInitializeProcessSecurity` 设置 Token，就是最开始的令牌。然后设置句柄表，如果是继承句柄的设置，直接复用父进程的 HandleTable。

接着应用 MitigationPolicy。`CreateProcessInternalW` 流程开头生成的 AttributeList，可以定义Policy。

1. MitigationPolicy 可以用来设置进程的一些自保护，达到阻止注入、限制DLL 加载之类的效果。
   1. 像部分 svchost.exe 设置了只允许微软模块，在DLL 注入时需要先去除这些设置。
2. 还可以动态设置父进程ID
   1. 像UAC 弹窗创建者实际是 consent.exe，但可以设置回发起创建请求的进程
   2. 这个功能经常用于将黑进程挂成白进程的子进程。
3. 可以设置的属性比较多，[https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)

之后开始往进程中填充内容了，`MmInitializeProcessAddressSpace`。将主程序的 Section 映射到当前进程虚拟地址空间 `MmMapViewOfSection`。MapView 是 `PspAllocateProcess` 中最主要的函数之二

映射，就是新建一个 MMVAD，根据 Section 大小找一段起始虚拟地址和结束虚拟地址，再根据 Section 中 Subsection 信息设置起始虚拟地址对应的起始物理页指针，就是创建 Section 时，SEGMENT Pte 数组位置。然后将 MMVAD 插入到`EPROCESS.VadRoot`。

创建 MMVAD 后，它设置的内存映射不会立即更新到进程页表中，要等到CPU 访问虚拟地址产生缺页异常才会使用 `MiCheckVirtualAddress/MiLocateAddress` 查找进程的 VadRoot，如果有 VAD 描述这个异常地址，再分配物理内存，更新页表。

这种对于资源的克制使用应该好好学习一下，现在很多软件动不动常态化的占用 10% 甚至更高的Cpu 以及大几百M 的内存，这是不合理的

主程序 Section 映射后，会将 NTDLL 的 Section 也挂进去，根据这些内容创建、填充 `EPROCESS.Peb`，到了这时，进程才从一个无属性的容器变成 xxx.exe 进程。接着从系统全局的 PspCidTable 中拿一个索引做 PID。

之后其他成员初始化大同小异

> 页表Hook
> 因为Windows 提供的API 对权限检查与设置比较严格，改页表变成绕过各类检查的方式。
> 使用场景，比如杀软或EDR 触发扫描时，一般针对Private 的、可执行内存。
> 举个例子，DLL 加载通知、线程开始通知这类事件，取新模块地址、线程入口、栈回溯调用链，通过 NtQueryVirtualMemory 查 VAD 获取这些地址的内存属性，一般来说，可执行代码对应的应该是 Shared+COW+X，进程主动分配的内存是 Private+RW+NX，如果出现 Private+RWX 或 Rip 处于栈范围之类，就十分可疑。那如果直接手动修改 PTE 的可执行、读写等标志位，VAD 条目并不会更新，就绕过了 QueryVirtualMemory 的检查，实现了可疑内存的隐藏。
> 还有一些场景是Hook。比如在进程回调时，找到想要Hook 的函数地址对应的物理页，复制出一张新的物理页，修改，然后替换，以绕过各类读写加载等 API 实现对当前进程的Hook。

### PspAllocateThread

进程对象创建完成，要让进程跑起来，需要创建一条线程。线程是操作系统的概念，Cpu 就只认寄存器，线程最基础的功能就是一个 Cpu Context 的管理者，非常粗略的说，把某线程对象的 Context 换到 Cpu 寄存器，就是线程切换了。

线程对象类型是 `PsThreadType`，对象结构是 ETHREAD，创建过程与进程类似。先创建对象，再初始化成员 Tcb(内核用)，拿线程 ID，初始化成员 Teb(R3用)，初始化 Apc 链表，把对象挂到进程中 `EPROCESS.Pcb.ThreadListHead`(枚举线程的各类 API 从这里取数据)。

线程栈 `ETHREAD.Tcb.StackBase`是内核分配的，默认 KeKernelStackSize 大小，Teb 中的`ETHREAD.Teb.StackBase` 是 Attach 到新进程中通过 `ZwAllocateVirtualMemory` 分配的，线程的R3 栈大小，可以在PE 结构头信息中设置。栈大小影响到使用的场景主要是在使用递归调用的时候，还有使用巨大的临时变量结构体之类的时候，每次递归要把部分参数、调用桢、局部变量压栈，容易触发栈用光的问题。所以win32k 的线程要用大内核栈。

Cpu 依靠Context 执行，线程获得执行总是依靠`SwapContext`，以此新线程无论内核还是用户态，都需要构造一个“`假装自己是一条正常线程只是被切换出去了`”的Context，对于用户态线程来说，这个Context 表明这条线程是 UserMode 的，正在执行`ntoskrnl!KiStartUserThread`函数。这个函数会调用`ntoskrnl!PspUserThreadStartup`，然后call 一次`KiDeliverApc`，然后通过`iretq`返回用户态。这个Context 的构造，就在 `KeInitThread`

`PspUserThreadStartup`在 NT4 时，主要是降IRQL，然后插一个指向`ntdll!LdrInitializeThunk`的UserMode APC，当线程返回用户态时，就会执行。现在是构造栈桢，设置好参数、返回地址以及各个寄存器的值，让退出到 R3 的地址直接变成 LdrThunk。Startup 中设置 Context 的函数是 `ntoskrnl!PspInitializeThunkContext`，在这个函数中首先调用 `PspCallThreadNotifyRoutines`，触发线程回调。然后构造两个栈桢：

1. 第一个 Rip 取的`ntdll!LdrInitializeThunk`

   线程切到 R3 InitializeThunk，根据条件执行进程的初始化操作。然后call`ZwContinue` 把第二个栈 Pop 出来，之前的栈清空

1. 第二个 Rip 取的`ntdll!RtlUserThreadStart`

   栈清空后，`ntdll!RtlUserThreadStart` 作为线程调用栈的第一个函数。这个函数默认使用 `__try/__except` 把要执行的代码包起来，中间调用`kernel32!BaseThreadInitThunk`，其中初始化 TLS 回调，然后 call 到真正的、用户设置的线程 StartAddress 执行

新线程的执行要等后续挂到 Cpu 关联的 `KPCR->KPRCB` 再说，此时线程分配结束。接着回到 `NtCreateUserProcess` 继续完成进程的创建。`ntoskrnl!PspInsertProcess`将进程对象挂到 `ntoskrnl!PsActiveProcessHead`。PG前所谓进程断链隐藏，就是断的这里了。接着调用 `ntoskrnl!PspInsertThread`

- 如果当前是主线程，先Call `PspCallProcessNotifyRoutines`，触发进程创建回调。
- 继续判断如果是 KernelMode 线程，它没有额外的栈桢要构造，在 Insert 这里直接 Call `PspCallThreadNotifyRoutines`
- 接着查看父进程的 Job，判断是否有 Job 需要关联，有的话就将新进程挂到 Job 对象的进程链表上 `EJOB.ProcessListHead`
- 再调用 `KeReadyThread`，这里会获取 Windows 给 CPU 调度相关定义的结构 `KPCR->KPRCB`，`KPRCB`里面有个链表 `DeferredReadyListHead`，将线程对象挂上去，Windows 会在陷阱事件中根据线程调度的规则从链表取数据并将线程的Context Swap 到Cpu 上。CPU 没有线程概念，靠寄存器设的值做事，线程的 Context Swap 到 Cpu 上，Cpu 就从新地址执行。线程调度这里面有一套根据线程优先级、系统负载等组成的规则，放后面

`KeReadyThread` 之后，线程就处于随时可能被执行的状态了，但是用户态线程默认创建的时候就塞了一个 Suspend APC，线程获得执行机会后，会先执行暂停的 Apc，这个Apc 里面就等待暂停信号归零。如果用户代码创建进程的参数里没有`CREATE_SUSPEND`，线程会在 `CreateProcessInternalW` 中恢复执行，如果设了，就要等用户代码自己手动继续了。

进程、线程都已经创建，这边完成后接着清理一下变量之类，准备返回 CreateProcessInternalW。

### Job

在上边 `PspInsertThread` 时，会检查 Job 的情况，在平时的工作中，Job 使用大概几种场景。

1. 最常用的操作就是控制进程同时退出。

   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`，一般在主进程创建一个 Job 对象，子进程创建时挂过去，子进程的后续进程都会自动继承。就是 `PspInsertThread` 中的流程。

   chrome 的多进程结构就是用 Job 关联的，主进程退出，子进程会跟着退出。这对于依靠某些重要组件才能干活的进程来说很适用。

1. 限制资源使用。

   可以限制用多少内存，多少 CPU 这样。跟 linux 的 cgroup 限制有点像

1. 设置优先级

   线程的时间片分配策略决定一条线程能得到多少执行时间，`PspApplyJobLimitsToProces`s 中，会调用`KeSetDisableQuantumProcess`，可以使用这个逻辑让Job 占用多数Cpu 时间

1. 还会用到的操作，就是补充 Token 的权限管理能力

   Win32k 并不是按照 NT 内核设计实现的，它的对象没有对象头，也就没有 SecurityDescriptor。所以我们能看到 OpenProcess/OpenThread/NtOpenFile 返回ACCESS DENIED，但从来没有 OpenWindow/OpenMessage，而是 FindWindow/GetMessage，直接取，有就能访问。

   对于这部分控制权限的缺失，Job 上面做了一些的弥补，[https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_ui_restrictions)。可以控制是否能切换桌面、用Job 进程外的句柄、读写剪切板等。

Job 是挂在会话下的，所以服务中的 Job 如果要给登录用户使用，需要 Impersonate 到用户环境创建。沙盒类产品比如 Sandboxie，逻辑里面一般都有 Job，搭配 低权限Token 使用

内核底下的创建部分可以总结为以下流程：

*NtCreateUserProcess*

   *→ MmCreateSection (Executable File)*

      *→ IRP_MJ_CREATE*

   *→ PspAllocateProcess (Process Object)*

   *→ MmCreateProcessAddressSpace (Page Table)*

   *→ MmMapViewOfSection*

      *→ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION*

   *→ PspAllocateThread*

      *→ PspUserThreadStartup*

         *→ usermode PspCallThreadNotifyRoutines*

         *→ R3 ntdll!LdrInitializeThunk*

   *→ PspInsertProcess*

      *→ ObpCallxxxOperationCallbacks (Process)*

   *→ PspInsertThread*

      *→ ObpCallxxxOperationCallbacks (Thread)*

      *→ PspCallProcessNotifyRoutines*

      *→ kernel mode PspCallThreadNotifyRoutines*

*→ return to R3 CreateProcessInternal*

## 配置新进程

进程对象创建完成后，回到 CreateProcessInternalW，接下来可以对进程的内容做一些初始化，首先 Windows 会通过 `kernel32!BasepIsProcessAllowed` 检查注册表项：

`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`

一段存在了很久的逻辑，这里可以设置DLL 做驻留。

### AppCompat

接着通过 kernel32!BasepQueryAppCompat 去取是否有绑定的兼容性设置，通常兼容性设置会存放在`\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers`。兼容性设置实现的载体是 aclayer.dll 和 apphelp.dll。

随着系统升级，有些 DLL 内的函数定义和行为发生了改变，为了不影响旧有程序继续运行，就要做一层官方 Hook，比如在 Windows 11 上以 Windows XP 兼容模式运行，就要改变 GetVersion 的返回值，有些 API 已经废弃的，就要帮这个 API 转接到现有的 API 上。

加载这个设置的是 Shim Engine，在 Ldr 初始化 `ntdll!LdrpInitializeProcess` 的时候应用。Windows 有一些数据库表在 `\Windows\AppPatch` 下面。AppPatch 下的表是可以编辑的，微软有一个官方的工具 Microsoft Compatibility Administrator，可以用这个工具对指定 EXE 生成配置，配置中可以定义修复逻辑从某个DLL 中加载。Windows 有内置的 sdbinst.exe 可以将新生成的配置安装到系统中。有利用这块逻辑做的持久化。

接着通过 `kernel32!BasepConstructSxsCreateProcessMessage` 创建一条到 csrss 的消息。WinSXS 消息返回后获取Shim 的详细配置 `kernel32!BasepGetAppCompatData`，在新进程申请一块内存存放，地址给 `Peb.pShimData` 指针，pShimData 在后续初始化进程时使用。

### WinSXS

进程间通信，明面上的技术有窗口消息、共享内存、socket、管道、内存映射等，实际用的比较多的，还是 ALPC 端口。

在进程创建过程中，创建者进程通过 ALPC 给 csrss.exe 发送 SXS 消息，以让 csrss.exe 创建一个 Activation Contxet，这个 context 用来辅助查找新进程的DLL 依赖。

`CsrClientCallServer(MsgHeader, MsgBuffer, (API Index)0x1001D, MsgSize);`

SXS 是 Windows 多版本组件共存功能的一种实现机制，就像有的 EXE 是 Visual Studio 2008 编译的，当时链接的 9.0 版本的 msvcrt.dll，放到 windows 11，可能系统默认 14.0 版本的 msvcrt.dll，旧的 EXE 需要运行就要帮助它找到正确版本的DLL 和路径。

WinSXS 的文件主要存放在 `\windows\WinSXS` 目录下。

有多种指定版本的方式

1. 在EXE 内嵌 manifest。这是最常见的，正常情况比如用 Visual Studio 编译完，都会默认带一个。
2. 在EXE 同路径与EXE 同名的 .manifest 文件。
3. 注册表定义的，统一设置的
+ Edge 内嵌 manifest 例子

```other
<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
  <security>
    <requestedPrivileges>
      <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
    </requestedPrivileges>
  </security>
</trustInfo>
<dependency>
  <dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" 
    	version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly>
</dependency>
<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
<application>
  <supportedOS Id="{e2011457-1546-43c5-a5fe-008deee3d3f0}"/>
  <supportedOS Id="{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"/>
  <supportedOS Id="{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}"/>
  <supportedOS Id="{1f676c76-80e1-4239-95bb-83d0f6d0da78}"/>
  <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
  <maxversiontested Id="10.0.18362.0"/>
</application>
</compatibility>
...
```

+ 发送给 csrss 的 SXS 消息格式

```other
- ReactOS 定义

typedef struct _BASE_SXS_CREATEPROCESS_MSG
{
    ULONG Flags;
    ULONG ProcessParameterFlags;
    HANDLE FileHandle;
    UNICODE_STRING SxsWin32ExePath;
    UNICODE_STRING SxsNtExePath;
    SIZE_T OverrideManifestOffset;
    ULONG OverrideManifestSize;
    SIZE_T OverridePolicyOffset;
    ULONG OverridePolicySize;
    PVOID PEManifestAddress;
    ULONG PEManifestSize;
    UNICODE_STRING CultureFallbacks;
    ULONG Unknown[7];
    UNICODE_STRING AssemblyName;
    ...
} BASE_SXS_CREATEPROCESS_MSG, *PBASE_SXS_CREATEPROCESS_MSG;
```

csrss.exe 通过监听 `\Session\X\Windows\ApiPort` 这个 ALPC 端口，接收到 SXS 的请求后，会尝试多种方式为这个 EXE 创建一个 Activation Context，这里 csrss 可能产生多个文件请求、进程访问请求、注册表搜索。安全软件需要考虑如何正确的在对象回调、注册表回调以及文件系统中过滤 csrss 的操作。

响应函数是 `csrss.basesrv.dll!BaseServerApiDispatchTable.BaseSrvCreateActivationContext`，随着功能的变迁，现在独立出了一个 sxssrv.dll，通过 `basesrv!BaseSrvRegisterSxS` 设置处理函数。sxssrv 这里更多还是Cache 管理、Policy 处理之类，真正生成是 `sxs.dll!SxsGenerateActivationContext`，处理流程比较长。

Context 存储的最重要的信息就是DLL 名字加运行环境对应加载路径。创建完成后，csrss.exe 进程填充新进程的Peb 中关于 Activation Context 的成员。

```other
Peb ...
  const struct _ACTIVATION_CONTEXT_DATA ActivationContextData;
  struct _ASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
  const struct _ACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
  struct _ASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;
```

也有找不到的，比如 manifest 定义依赖不存在的 20.0 版本的 common control dll，此时就会出现经典的 SXS 错误弹窗：

> 应用程序无法启动，因为应用程序的并行配置不正确，有关详细信息，请参阅应用程序时间日志，或使用命令行sxstrace.exe工具

+ Activation Context 结构

```other
- ReactOS 定义

typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset;
    ULONG ExtendedTocOffset;
    ULONG AssemblyRosterOffset;
    ULONG Flags;
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;
```

这个结构在后续解析导入表时使用。

在加入 WinSxs 的逻辑前，这里的通知主要是 call 到 `csrss.csrsrv! CsrServerApiDispatchTable.CsrCreateProcess`。现在相当于增加了一个功能。

csrsrv 模块是 NT 进程、线程与我们看到的窗口、交互、输入之间的桥接点，NT 的进程线程创建后，csrsrv 会 Duplicate 进程、线程句柄，设置目标进程的 ExceptionPort，在本模块维护一套会话、进程、线程关系。这套关系会广泛的应用在窗口管理、输入输出等功能上，后边会用到。

### ALPC

ALPC 对于 Windows 的重要性，与 osx 的 XPC、linux 的 unixsock 类似，操作系统广泛使用。它最大的优点就是内存交互。在 Windows 上像管道、socket 这类要走各自的协议栈会影响性能。ALPC 不对外披露细节，功能给人模糊的感觉，这其实是不应该的，没必要藏。这个功能很重要，Windows 平台做跨进程通讯比Pipe SOCK 共享内存之类要好的多

ALPC 对象创建后会挂在 `ntoskrnl!AlpcpPortList`，过去只有 LPC 的时候，结构体中没有等待对象，也没有对消息进行 Csq 队列处理，不能 Async，NT5 扩展了异步在内的多项功能，取代了 LPC，为了兼容旧代码，在 Pharse1 初始化时设置两个类型一致。

```other
- Win11 Pharse1 初始化
LpcPortObjectType = AlpcPortObjectType;
LpcWaitablePortObjectType = AlpcPortObjectType;
```

+ NT4 LPCP_PORT_OBJECT

```other
typedef struct _LPCP_PORT_OBJECT {
    ULONG Length;
    ULONG Flags;
    struct _LPCP_PORT_OBJECT *ConnectionPort;
    struct _LPCP_PORT_OBJECT *ConnectedPort;
    LPCP_PORT_QUEUE MsgQueue;
    CLIENT_ID Creator;
    PVOID ClientSectionBase;
    PVOID ServerSectionBase;
    PVOID PortContext;
    ULONG MaxMessageLength;
    ULONG MaxConnectionInfoLength;
    PETHREAD ClientThread;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SECURITY_CLIENT_CONTEXT StaticSecurity;
    LIST_ENTRY LpcReplyChainHead;           // Only in _COMMUNICATION ports
    LIST_ENTRY LpcDataInfoChainHead;        // Only in _COMMUNICATION ports
} LPCP_PORT_OBJECT, *PLPCP_PORT_OBJECT;
```

+ Windows 11 22H2 ALPC_PORT

```other
typedef struct _ALPC_PORT
{
  +000 struct _LIST_ENTRY PortListEntry;
  +010 struct _ALPC_COMMUNICATION_INFO* CommunicationInfo;
  +018 struct _EPROCESS* OwnerProcess;
  +020 struct _KQUEUE* CompletionPort;
  +028 void* CompletionKey;
  +030 struct _ALPC_COMPLETION_PACKET_LOOKASIDE* CompletionPacketLookaside;
  +038 void* PortContext;
  +040 struct _SECURITY_CLIENT_CONTEXT StaticSecurity;
  +088 struct _EX_PUSH_LOCK IncomingQueueLock;
  +090 struct _LIST_ENTRY MainQueue;
  +0a0 struct _LIST_ENTRY LargeMessageQueue;
  +0b0 struct _EX_PUSH_LOCK PendingQueueLock;
  +0b8 struct _LIST_ENTRY PendingQueue;
  +0c8 struct _EX_PUSH_LOCK DirectQueueLock;
  +0d0 struct _LIST_ENTRY DirectQueue;
  +0e0 struct _EX_PUSH_LOCK WaitQueueLock;
  +0e8 struct _LIST_ENTRY WaitQueue;
  union
  {
    +0f8 struct _KSEMAPHORE* Semaphore;
    +0f8 struct _KEVENT* DummyEvent;
  }; /* size: 0x0008
  +100 struct _ALPC_PORT_ATTRIBUTES PortAttributes;
  +148 struct _EX_PUSH_LOCK ResourceListLock;
  ...
  +1d0 unsigned long CanceledQueueLength;
  +1d4 unsigned long WaitQueueLength;
} ALPC_PORT, *PALPC_PORT; +size: 0x01d8
```

为了支持异步，消息通过 ALPC 发送时，必然要经过一次拷贝，所以消息最好短一点，以减少内核中的消息内存分配和拷贝的操作。建议大多消息的长度不超过 0x200。

查看`ntoskrnl!AlpcpSendMessage`。内核中 ALPC 快速内存分配表 `AlpcpLookasides` 元素的长度是 840，在 Windows 11 22H2 是这样，减去一个分配表头 `KALPC_RESERVE`(48)，再减一个 `KALPC_MESSAGE`头(240)，再减去 `PORT_MESSAGE`头(40)，传递消息是 `Message Body` 可用大小为 512=0x200。超过大小也没事，不用快速表改为 `ExAllocatePool` 分配。

发送消息时，消息的属性可以反复使用，在属性中可以设置传递具柄和Section。在创建端口时 Port 的属性设置允许自动 dup `ALPC_PORTFLG_ALLOW_DUP_OBJECT。`在消息属性中可以设置：

- `(_KALPC_VIEW) KALPC_MESSAGE_ATTRIBUTES.View`
- `(_KALPC_HANDLE_DATA) KALPC_MESSAGE_ATTRIBUTES.HandleData`

这样收到消息的一方可以通过 `ntorkrnl!AlpcGetMessageAttribute` 将内容取出来，可以当作一种节省 Buffer 长度的方法。消息属性用起来还是有点麻烦，手动在 Server 端打开 Client Process 主动Map Section 和 Dup Handle 可以达到一样的目的

ALPC server 的粗糙流程，它的模型参考 socket，大体是一致的

1. `AlpcCreatePort`
   1. 创建一个 `ALPC_PORT` 的对象，创建内部数据索引的 `Communication` 结构
   2. Alpc 端口可以挂 `IoCompletionPort`，多起几条线程做响应
2. `SendAndReceivePort`表面意思，发送消息并等待回复
   1. 锁起来，检查几个`DirectQueue/WaitQueue/PendingQueue/MainQueue`
   2. 没消息就 `SignalAndWait` 等事件 `Semaphore`
3. 取到消息
   1. 根据取到的 `PORT_MESSAGE.u2.s2.Type` 确认消息类型
   2. 处理消息，比如 `AcceptConnectPort` 建立连接， `SendAndReceivePort` 回复、`DisconnectPort` 断开之类
   3. 处理完成，Reply 或者不需要 Reply 的收到即可，内核根据 `KALPC_MESSAGE.WaitingThread`，设置`WaitingThread.KeyedWaitSemaphore`。这边设置了，如果对面有等待的，就Signal 了

ALPC Client 的粗糙流程

1. `AlpcConnectPort`，连接一个指定名字的端口，主要校验端口名和连接权限
2. `SendAndReceivePort` 发送，跟Server 调用的没区别
   1. 用户态构造、发送的是 `PPORT_MESSAGE`，内核分配一个 `KALPC_MESSAGE` 包起来，同时通过 `ExCreateHandleEx(AlpcMessageTable` 为这个消息创建一个 Message ID
   2. ALPC 消息总是跟线程绑在一起的，绑定时将 `KALPC_MESSAGE.WaitingThread` 设置为当前线程，线程 `ETHREAD.AlpcMessageId` 设置为消息的指针，然后可以准备投递
   3. 根据不同的情况，将 `KALPC_MESSAGE.Entry` 挂 `ALPC_PORT.DirectQueue/WaitQueue/PendingQueue/MainQueue`
   4. 如果设置了等待回复。挂完后等待`CurrentThread.KeyedWaitSemaphore`

> 回到创建进程的主流程上，从内核回到 CreateProcessInternal 这段无甚可说，最重要的就是往 csrss 通知了一下，一方面是记录有这么个进程启动，一方面是生成一下 Activation Context

## 新进程的初始化

Sxs 完成，CreateProcessInternalW 也差不多完成了它的使命，对新进程调一次 ResumeThread，新线程的暂停信号终于清零，开始执行了。

从这里开始，CreateProcessInternalW 退出，后续的执行就与创建者进程无关了。

### LdrInitializeThunk

在内核下构造的栈帧此时得到执行。这一段 Thunk code 先初始化Ldr，然后ntdll!ZwContinue 转到 ntdll!RtlUserThreadStart。

```other
void __fastcall __noreturn LdrInitializeThunk(
    struct _CONTEXT *a1, void *a2, void *a3)
{
  unsigned int v4; // eax

  LdrpInitialize(a1, a2, a3);
  v4 = ZwContinue(a1, 1u);
  RtlRaiseStatus(v4); // 正常情况下这里是不会调到的
}
```

`ntdll.LdrpInitialize` 主要做的事情就是设置进程的运行环境，像堆设置、注册表设置以及模块的初始化等等。占最大篇幅的是解析导入表，初始化引用的模块。

在 22H2，先执行了一个跟 Silo 相关的 `LdrpInitializeHotPatching`，代码比较丑陋，略过。

然后真正做事的 `LdrpInitializeProcess`。先初始化语言设置，创建进程的堆。初始化异常链表，将 Exception Directory 中的项插入到 `ntdll!LdrpInvertedFunctionTables`。自己做 DLL 手动加载这里的处理不要忘了。

继续 `LdrpInitializeExecutionOptions`，这里会检查各种执行 Flag，gflags、AppVerifier 的设置。打开 `\KnownDlls` 的对象目录，里面是系统一些 DLL 的 Section，加载 DLL 时会优先搜索这里。初始化当前工作目录，当前工作目录的 DLL 加载优先级是比较高的。然后如果是 dotnet，加载 mscoree，这是 dotnet 的 ntdll。接着有一个 `LdrpInitializeImportRedirection`，加载 `NtCurrentPeb()->ProcessParameters->RedirectionDllName` 这个 DLL，AppX 用的，可以替换导入表函数，相当于一种导入表Hook。

继续往前 Load kernel32.dll，kernel 和base 是一起的。ntdll 和 kernel32 是基础 DLL，所以手动优先处理这两个模块，之后就可以照着导入表循环加载了。DLL load 还是 Section MapView 那一套逻辑，像 kernel 模块，找 KnownDlls 下的 Section Object，MapView 进来即可。

接着检查 Peb->pShimData，如果有值，加载 apphelp.dll，`apphelp!SE_InitializeEngine` 解析这段 Data 提取 sdb 信息存起来，所以这个 DLL 有些进程会加载有些不会。

前边环境准备好，接下来 `LdrpMapAndSnapDependency` 拿着 IMPORT DESCRIPTOR 遍历主程序导入表，加载依赖。加载过程可以简单概括为：

1. 根据导入表 DLL 名字查找已加载或已Map DLL
2. 根据系统的设置，确定 DLL 路径
3. 以 Section 的形式加载 DLL

导入表DLL 只有一个名字，但机器上重名 DLL 的概率可不低。组成 DLL 路径有目录选择的优先级，微软有个页面讲加载优先级，[https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)，这边根据 LdrpLoadDll/LdrpMapDllSearchPath 的流程大概整理。

1. 只讨论解析导入表，LoadLibrary 原始参数是完整路径的不参与流程
2. 先用DLL 哈希查是否已加载过
3. KnownDlls 对象目录
4. WinSXS 指定的
5. 主程序所在目录
6. 系统目录 System32、Windows

DLL 加载路径的选择，代码比较繁杂，也可以 SetDllDirectory 指定唯一路径。因为加载顺序问题，DLL 劫持经久不衰。做一个导入表中同名的 DLL，代理它的导出表，再利用加载顺序或改变加载顺序，比如放到进程文件的目录下，以此让进程加载中间DLL。

在处理 DLL 路径时，有个函数叫 `LdrpApplyFileNameRedirection`，这个函数开头有个奇奇怪怪的调用 `ApiSetResolveToHost`。它关联到在日常使用 Windows 时，偶尔发生奇怪的弹窗：

> The program can't start because "api-ms-win-xxxxxxx.dll" is missing from your computer, Try reinstalling the program to fix this problem.

这个DLL 缺失消息本身不奇怪，主要是 api-ms-win-xxxx 和 ext-ms-api-xxxx，系统中并没有对应的 DLL 文件，而且很多 PE 中的导入表确实是写着从这两类 DLL 导入而且运行正常。尝试理解设计原理，微软是想把同类的操作抽象出来，[https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets)

总之这些 DLL 设计之初就是没有真实文件的，除非微软新写的，在系统初始化的时候，内核将`\System32\apisetschema.dll`映射到内存里，记录在 `MiState.Sections.ApiSetSection`，后面有新进程启动，就把这块 Section 挂到新进程`EPROCESS.Peb.ApiSetMap`。这块 Section 里面定义了所有虚拟DLL 的名字和对应的真实 DLL 名字，等到了加载 DLL 的时候， `ApiSetResolveToHost`就将虚拟DLL 名字换回真实 DLL 名字，之后DLL 加载就使用真实名字，流程不变。解析可以参考 [https://github.com/zodiacon/WindowsInternals/tree/master/APISetMap](https://github.com/zodiacon/WindowsInternals/tree/master/APISetMap)

总之感觉这个功能有点鸡肋了，而且造成了一堆 DLL missing 问题，开发者也经常搞得莫名其妙。

之后就是搜索 ActCtx。有个判断 `LdrpIsSecureProcess`，安全进程不搜索 ActCtx，安全属性来源于创建进程的时候给 CREATE_SECURE_PROCESS。

`ntdll!LdrpApplyFileNameRedirection`

   → `ntdll!ApiSetResolveToHost`

   → `ntdll!RtlDosApplyFileIsolationRedirection_Ustr`

      *→ `sxsisol_SearchActCtxForDllName`*

      → `RtlFindActivationContextSectionString`

      → `search (Peb.ActivationContextData)`

中间这个 FindActivationXXX 是 Sandboxie Hook 了做注入的函数。在这里注入有 2 个优点，1 是进程空间才加载 ntdll 和 kernel，注入的时机很早，可以 Hook 后续 DLL 的入口函数。2 是这个时间可以构造 ActCtx，用来改变、伪造DLL 的加载路径。不过缺点是这里时机太早，注入的 DLL 最好导入表只依赖 ntdll，CRT 也还没初始化，STL 不能用。

DLL 路径确认后，就是 Section 创建那一套。加载完成，就会链接到 `Peb.Ldr.InxxxxModuleList` 列表中。使用 `GetModuleHandle / EnumProcessModules` 等 API，其底层遍历的就是这张表，从这几个链表中断开，可以从大多数正规的 Windows API 中隐藏模块。

每个 DLL 加载都会递归调用解析导入表的操作，每当一个 DLL 完成加载，就会调用它的 Tls 函数和 DllMain。这里需要注意的是，call 进 DllMain 时，线程正拿着`Peb.LoaderLock`。

这里有个经典的卡死问题。在 DllMain 中创建一条线程，并等待线程执行结束。`Peb.LoaderLock`是临界区类型，解析导入表的这条唯一的主线程可以重入，所以递归加载 DLL 重复获取这把锁没问题，但如果新开线程不小心访问到这个锁，就得等主线程释放了，而主线程得跑完 DllMain 才能释放。

有不少场景可能会访问到这个锁的，[https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)。DllMain 还是尽可能简单一点，比如不要调用 LoadLibrary，因为很难判断要调用的 DLL 或者它依赖的 DLL，初始化函数中是否牵涉 Loader 锁的操作。

Windows R3 有一个官方提供的监控DLL 消息通知的接口，LdrRegisterDllNotification，不过收到消息时对应的 DllMain 还未执行，有些 Dll 全局变量未初始化。

DLL 加载完成，`apphelp!InstallAfterInit` 会执行预设的 shim。

### → Win32

在导入表解析过程中，加载模块 DllMain 做了不少初始化的工作。3 个比较经典的 DLL。

**Kernel32**

Kernel32 依赖 Kernelbase。

- 在 kernelbase 的DllMain 函数 KernelBaseDllInitialize，会连接到 csrss!BASESRV，主要是为了注册 CtrlRoutine。
- 初始化 wil 库，wil 是 windows 封装的一套 c++ 库，包括线程、COM 等组件，Windows 有大量 R3 的 binary 使用 [https://github.com/microsoft/wil](https://github.com/microsoft/wil)。
- 将 `KernelBase!UnhandledExceptionFilter` 注册到 ntdll 以支持 SEH 回调。
- 如果是控制台进程，则需要打开 `\Device\ConDrv`设备，通过DeviceIo 操作请求一个控制台窗口，并绑定 Input/Output。控制台的逻辑也几经变化，最初控制台窗口由 csrss 提供，后来独立出一个负责窗口的 conhost.exe 但逻辑依然是csrss 处理，win81 再独立出一个 condrv.sys，conhost的创建、控制台程序与窗口之间的交互，由condrv 来传递。conhost 是直接在 condrv 驱动底下由 `ZwCreateUserProcess` 创建的。

**user32**

user32 的入口 `UserClientDllInitialize` 中，需要初始化内核与窗口交互的关键结构。从这里开始，进程中才会有界面、窗口相关的内容。

> win32k 图形部分其实与 NT 内核没什么关系，如果按照 NT 的设计，首先应该把窗口、光标、消息之类定义为NT Object，操作这些对象的相关API 放在 R3，然后通过 syscall 进内核，通过 Ex/Ke/Ob API 访问对象并检查访问权限，再通过发 Irp 调用图形设备做绘制，再调用图像设备显示界面。真这一套下来系统的效率肯定还是很优秀的，但用户交互的感知就很不好了
- > 为了减少内存拷贝和上下文切换，win32k 窗口与图形常用的工作线程都在内核运行，比如桌面窗口、键盘鼠标消息、窗口数据管理等
- > 其次win32k 窗口数据用的Session Space，Session 内都是共享的，这使得win32k 可以直接在内核底下改任意进程的win32 数据而不需要切换页表。直接操作消息队列进程间通信也省了
- > 做一个共享内存区`win32k!hSectionShared`，以此内存区创建Heap，将R0/R3 要操作的内存从这里分配，再 map 到每个 GUI 进程，再对内存配一个句柄表和对应操作句柄的函数，做一个管理结构`(tagSHAREDINFO)win32k!gSharedInfo`把这些包起来对R3 隐藏实现。这样 R0与R3 交互的内存可以避免拷贝
- > 不使用NT 对象，也不用DACL。gdi 和dxg 不做成设备，直接当前内核栈调用
- > 减少与图像显示设备的交互，在内存画完再一次性提交，双缓冲/多缓冲
> 这样削减了内存拷贝、进程/线程切换、IRP投递、内核栈切换

图形与窗口是关联到登陆会话的，换个角度，如果以 Console 的模式登陆系统，就不需要加载win32k 这一堆功能了，参考DOS，可以直接用中断

- 在第一个用户进程 smss.exe 运行后，会创建第一个可交互的 session，并为这个session 创建 csrss.exe 和 winlogon.exe，smss通过调用 `SystemExtendServiceTableInformation` 让内核加载 win32k 的驱动，win32k 在 `DriverEntry` 中 load `dxgkrnl` 和 `base/full/sgd` 那几个 sys，扩充 ShadowTable

在 csrss.exe 的启动过程，它会加载管理图像的 winsrv.dll

- 在这个dll 的 `UserServerDllInitialization` 中，load win32u.dll，执行 `NtUserInitialization` 转到 `win32kbase!Win32UserInitialize`，这个初始化逻辑是 Session 级别的，每个登陆会话都会有一个新的初始化过程。在win32k 中，通常不使用常规的 `MapViewOfSection` 而是 `MmMapViewInSessionSpace`，就是之前创建进程时构造页表映射的那块会话的部分。在这里要创建 `ghSectionShared` 共享内存区，并从共享内存区创建 User Object 要用到的堆和对应的句柄表
- winsrv 会开启`RawInputThread` 线程，调用到 win32k 中读键盘鼠标的循环中。键盘鼠标事件由中断产生后提交到比如KbdClass，而Raw 线程则不停的读取，然后以消息的形式发送给 LowLevel 的Hook 或者放到 Foreground 线程的mlInput 队列中

NT 线程与 GUI 线程最大的不同，就是线程绑定了win32k 的各种资源，对应线程与进程字段填充了 `EPROCESS.Win32Process`、`ETHREAD.Win32Thread`

初始化内核驱动时，win32k 通过 `KeAddSystemServiceTable` 把支持的 syscall 加到 `ntoskrnl!KeServiceDescriptorTableShadow`，发生syscall 时，内核先检查标记`ETHREAD.ThreadFlags.GuiThread`，当这个 bit 有值就用 ShadowTable，有些在内核底下操作窗口的，先检查一下线程上下文是不是GuiThread

而线程变成 GuiThread 主要场景是调用`KiConvertToGuiThread`，其中调用win32k 给的回调函数

1. 回调函数 `ntoskrnl!PsWin32Callback` 由`win32k!W32CalloutDispatchThunk`填充
2. Thunk 中调用 `win32kfull!W32pThreadCallout/W32pProcessCallout`
   1. 转到 win32kbase 对应的 `UserThreadCallout/xxxUserProcessCallout`
   2. 两个callout 中分别创建 `ETHRAD.Tcb.Win32Thread`和`EPROCESS.Win32Process`，在GUI 开发中场景的`PsGetThreadWin32Thread`就取的这里
   3. `Tcb.Win32Thread&Teb.Win32ThreadInfo`，同一个东西，Teb 的是完整版
      1. ThreadInfo 广泛使用在 win32k 逻辑中，一般表示为 `pti/ptiCurrent`，创建进程的时候，参数里面窗口相关的设置之类，就应用在这里
      2. 参与消息处理的有 3个队列
         1. 键盘和鼠标事件，FIFO队列`pti->pq->mlInput`
         2. Post消息，FIFO队列 `pti->mlPost`，存储PostMessage 消息
         3. Send消息，单链表`pti->psmsReceiveList` ，存储SendMessage 消息，例外情况是在相同 `pti` 下直接调用 WndProc，不进队列
   4. `EPROCESS.Win32Process`
      1. 关联 DESKTOP，通俗意义的桌面，管理在上面显示的各类窗口，最常见的是 explorer 的 ShellWindow。其次用来隔离消息，消息传递不能跨桌面
      2. 关联 WinStation。这里的主要资源是剪切板和 AtomTable。一个登陆会话可以创建多个 WinStation，一个WinStation 可以创建多个 DESKTOP
3. 成功完成的话，就设置 `ETHREAD.ThreadFlags.GuiThread = 1`
4. Win32 与线程绑的太死，跟消息相关的操作必须处于正确的线程上，否则 Tcb.Win32Thread 取错，这使得窗口与线程过于耦合

User32 DllMain 的主要流程：

- 连到当前进程所属 Session 的 csrss!CSRSRV，csrss 里面为这条线程设置ClientInfo
- 初始化 Imm 输入法相关模块。imm32.dll，可见输入法的注入也很早
- 设置`EPROCESS.Peb.KernelCallbackTable`
   - win32k 本身需要频繁操作比如窗口内数据、剪切板等，所以 ntoskrnl 为它留了个内核调用用户态的口子 `ntoskrnl!KeUserModeCallback`，参数给API 序号，调到对应 R3 `ntdll!KiUserCallbackDispatcher`，在 ntdll 的这个函数中，通过 API 序号索引 `Peb`，就找到了 user32 填充的函数指针，调用完成之后再`ZwCallbackReturn` 回到内核。

   KernelCallbackTable 的值初始设置为 `user32.apfnDispatch`，但有许多逻辑会改变它。这里也经常被Hook，比如 `__ClientLoadLibrary` 这一条，通过 `user32!SetWindowHookEx` 注入的模块走这个回调加载进来

- 初始化 Gdi

   `GDI - Graphics Device Interface`，是Windows 主要和基础的图形引擎，提供了多种多类绘制函数。GDI 的初始化有个比较巧妙的 `NtGdiInit`。这是进程运行后第一个 call 到 win32k 的函数。本身这个函数并没有做什么事，关键在于进入 syscall 时，如果 API Index 超出了 NT 的 ServiceTable，则会 `KiConvertToGuiThread` 尝试程转为 GUI 线程

   ntoskrnl 调到 win32k Callout，线程加载时已注册到 csrss!CSRSRV，pti 初始化时可以从 Teb 得到正确的 `Win32ClientInfo`，关联到桌面和 WinStation。之后就创建pti/Win32Process 之类的。再`KeUserModeCallback`调用`user32!_ClientThreadSetup`把需要用到的win32 资源初始化

   `user32!apfnDispatch [_ClientThreadSetup]`

   - call `NtProcessConnect` 进入 win32k 打开 `ghSectionShared`
   - 加载 AppInit_DLLs
      - 这是一个经典的注入位置了，Gui 进程都会进入，而且目前程序运行的位置也很早，是一个较好的位置。加载逻辑`kernel32!BasepLoadAppInitDlls`

Windows 的 win32k 从设计上来说已经优化的比较极致了，多数时候发生界面卡顿或者未响应之类的问题，除开程序程序中有崩溃或者句柄泄漏，还有些是与它本身设计相关联需要注意的地方

现代操作系统对桌面的显示大概分成以下几个部分

1. 提供一个窗口管理器，负责逻辑窗口的部分
2. 提供一个图形引擎的上下文，比如画布
3. 绘制事件发生时，应用程序通过图形引擎提供的 API，在窗口所属的画布上画出自己的位图，提交给窗口管理器
4. 窗口管理器或者专门的窗口合成器按照窗口位置、Z轴将所有的位图合成一张最终的位图
   1. 另外处理类似透明效果、阴影等
5. 合成器通过显示设备提供的接口将最终位图封装成特定格式，发送到显示设备的缓存中
6. 显示设备从缓存取数据并展示

> ❓截图
> Windows 的窗口管理器在 win32k 中，画布有传统的 DC (Device Context)、Bitmap 位图，还有 DirectX 中的 Surface
> 图形显示关注 4 个角色
1. > 硬件设备，它有显存，这是最终要操作的地方。
2. > 图形引擎，它是一堆API 合集，可以在画布上画画
3. > 画布，是一块内核缓存区域，不同引擎支持的缓存格式可能不同
4. > 窗口，是一个逻辑概念，通过响应 PAINT 事件将自己的形象画到画布上
> gdi (Graphics Device Interface) 图形引擎比较有历史了，主要还是面向Cpu 的渲染模型，使用 DC 作为画布。DirectX 与之相比起来，针对 Gpu 的架构设计带来了更好的性能，充分利用多核心的并行能力可以大大减少任务过程的等待。之前主要给游戏用，现在系统本身大量使用。主要画到 Surface，也可以画到 DC
> 响应窗口的 WM_PAINT时，需要在画布上画出位图，可以用 gdi 提供的各类 DrawText/Image，也有 DirectX 提供的 Direct2D/DirectWrite，DC 或者Surface 本身的内存都是存放在内核下，画好后窗口管理器 win32k 将所有窗口合成整体图像，win7 增加了 dwm.exe，完成窗口合成与阴影、透明等功能，完成后通过 dxgi 的接口发送到内核显示设备中
> 在做屏幕截图时，有些是通过对桌面窗口进行 BitBlt 复制画布中的位图来实现，顶层桌面窗口由csrss!WINSRV 初始化的时候调到 win32k 创建，虽然我们肉眼所见的窗口都属于桌面的子窗口，位图大都会画在这个大 DC 上，但是使用 DirectX 的程序一般不画到这里，它一般直接画到内核缓存，还有 dwm 窗口合成器做的窗口透明、阴影等也不在这个 DC 上，dwm 等桌面窗口画完再取位图再加上的透明、阴影等效果，所以 BitBlt 不是一个好方法
> 其次可以考虑的是dwm，因为dwm 做最终的图像合成，并通过 dxgi 接口将位图发送给显示设备，那么只要在发送之前将位图取出转换到需要的格式即可。这是一种比较好的方式，但需要对 dwm 中使用 dxgi 接口时做 hook，对代码的稳定性要求较高
> 再往底层考虑就是过滤显示设备的IRP，Windows可能也是考虑到截屏与录像的需要，对虚拟显示设备做了一套 Graphics Capture API 的封装，可以认为是 Windows 从显示过滤设备中提供的一个对外接口，使用这套API 可以创建一个过滤设备并取位图，将位图转化成合适的格式即可

出现卡顿或转圈一般是绘制流程出现堵塞，范围大一点的是堵塞 csrss!WINSRV 的线程，表现为系统整体的响应延迟。范围小一点的就是堵塞自己程序的消息循环

系统范围内的堵塞，除去其他ALPC/IO 等待此类的逻辑问题，从窗口与消息出发，大多是全局消息造成的影响，比如键盘鼠标消息

> 发展变迁来看，过去键盘鼠标消息是直接操作Device，如今将 Input 做成了对象，以此增加过滤层，更方便的支持扩展键盘、虚拟键盘
> \-- csrss LoadLibrary <> winsrv.dll!ServiceTable
> \-- win32kfull!RawInputThread
   > \-- win32kbase!CBaseInput::InitializeSensor<>RegisterDispatcherObject<>ProcessInput
      > \-- win32k!RIMStartDeviceRead / rimInputApc <> Kbdclass->DeviceRead
         > \-- IRP READ
         > \-- IRP Pending -- 等待Complete
         > \-- win32kfull!xxxReceiveMessage & win32kbase!ProcessKeyboardInputWorker
            > \-- Translate VK&Code
            > \-- Low level hook procedure → **SendMessageTimeout (WM_HOOKMSG, ...**
            > \-- PostInputMessage (WM_INPUT, ...
            > **-- StoreQMessage(foregroundWindow->pti->pg->mlInput, ...**
> 中断产生键信息
> \-- IDT → Keyboard DPC → Kbdclass.KeyboardClassServiceCallback → Complete Pending IRP

键盘消息是一个较为典型的系统消息例子，`SetWindowHookEx` 设置的 LowLevel Hook 是以 SendMessage 的形式发送的，所以LowLevel 的 Hook 卡住比较影响系统整体。自己程序中处理 WM_KEY 相关的内容时倒无所谓，因为它这里是 Post 到 pg->mlInput 里面

绘制消息

绘制消息的起点是 `Invalidate`，就是使一块区域无效，这个动作可以由App 自己发起，也可以由系统线程发起。绘制有一个自身的限制，绘制大量操作像素点，是计算密集型的操作，耗Cpu。过多的绘制其一性能消耗会提高，其二响应其他消息会延迟。这里设定区域无效后，这块矩形区域被放到 `hWnd->hrgnUpdate` 并设置`pti->WakeBits`，但默认不会立即发出重绘的请求，后续如果还有 `Invalidate` 会将新区域合并在 `hrgnUpdate` 中。这个操作有助于减轻绘制的负担，如果要立即绘制，可以使用 `UpdateWindow`，在Update 函数中，user32 会直接发起一个 `xxxSendMessage(WM_PAINT)`

在App 消息循环 `GetMessage` 中，会优先处理`Win32ThreadInfo` 中的 3个消息队列，当队列中没有数据时，再检查 `pti->WakeBits & QS_PAINT`，类似的还有Timer 消息处理优先级更为靠后。处理 QS_PAINT 时，其中通过`pti->pDesktop->pwnd`找到第一个窗口，然后循环遍历该桌面的所有窗口，当找到属于当前 `pti` 的窗口时，以窗口的父子顺序，从子到父 `xxxSendMessage` 往每个窗口发送 `WM_PAINT`

这里的PAINT 消息是阻塞的，有设置超时。从设计上看，在绘制时或者绘制函数内部，最好不要产生新消息，绘制应该是纯粹的调用图形引擎在画布上画完即走，速度要快

`GetMessage` 中对于绘制消息的处理偏后，`mlInput->psmsReceiveList->mlPost->QS_PAINT->Timer`虽然这样有助于提高性能降低CPU 的使用率，但同时如果程序的消息队列比较繁忙，很容易造成界面上的刷新延迟，产生卡顿、延迟问题。这里面就包括有些使用`WM_COPYDATA`来做远程通信的，DropHandler 或者是 SendMessage 传递大量内容的。消息多或者单个消息处理慢

所以对于窗口与消息来说，与它本身设计相关联的

1. 为了尽快的处理消息，且降低Cpu 的使用率，将绘制的优先级降低
   - 这使得我们在需要更快的绘制时，主动调用 `UpdateWindow/Redraw`，这个函数通过`SendMessage` 将 PAINT 请求发送到 `psmsReceiveList`
   - 尽量保持消息队列不拥堵以减少主动PAINT
1. 为了减少进程间交互消耗，win32k 内部资源没有进程隔离，与线程强绑定，窗口与消息循环限定在单个线程中。`Get/DispatchMessage` 直接操作`pti`
   - 这使得程序内部可能产生互锁，尤其是业务中还有数据Mutex 锁之类的时候。大多发生于Send处理函数往其他线程Send，其他线程再Send 到本线程
   - 处理函数往相同线程Send 会直接调WndProc 避免堵塞
1. Windows只提供消耗小、非线程安全的基础实现
   - 创建Window 的线程需要与消息循环的线程保持一致，单线程的任务处理能力有限
   - 开发者需要自己合理安排Send/Post 以及多线程Worker。Send 需要发送者和接收者都堵塞，Post 不堵发送者，但接收者处理时堵塞。任务需要耗时较长时，最好分离消息循环线程与工作线程，中间可以使用 锁+队列+`PostThreadMessage`通信
3. combase.CoInitializeSecurity

这是在各类程序中都能看到的函数调用。在基础的 nt/kernel/user 之后，其他的功能性的 DLL，在提供功能时，往往并不直接到处函数，而是导出接口

这里就引申到一个重要机制，DCOM

### → RPC与DCOM

Rpc 是操作系统发展到一定阶段必然会出现的产物。通俗意义讲 Rpc 就是 Remote Procedure Call 远程过程调用，这里的远，指的是不同进程或者不同主机。

如果一段代码，需要被频繁使用时，同个 Project 里面可能抽象出来一个 h/cpp，用的时候 include 一下。如果分属不同进程或模块，大多是做成 DLL 即可。如果当抽离的模块中有状态和数据需要多进程共享，就需要做成服务，对外提供接口，响应请求。如果调用功能的程序和服务不在同一台机器上，接口调用就需要走网络

当功能与模块变多时，或者模块间的关系需要重新组织时，就特别需要一个机制，能够隔离模块物理位置、传输协议等带来的代码变化，这样功能与模块才能灵活的组织在一起。所以Rpc 是具有一定复杂度的系统必然产生的

首先当然要明白Rpc 如何对外提供功能：

服务进程运行后，对外提供功能，可以使用多种数据通信方式。有些产品选择自己写Pipe/SOCK Server 来处理。Windows 自己做了一套处理模型，类似 sock，叫做 RpcServer。光有Server 没有数据传递不行，为通信的过程中参数数据的序列化/反序列化使用了一种`Ndr - Network Data Representation`的数据协议。对于数据传递的通道，实现了socket/PIPE/ALPC 等。3 个部分结合起来，就是完整的Rpc 服务模型

Windows 使用 IDL 模型来标准化一个Rpc 服务，同样使用 IDL 模型的还有 Java 的 CORBA。[https://learn.microsoft.com/en-us/windows/win32/midl/midl-start-page](https://learn.microsoft.com/en-us/windows/win32/midl/midl-start-page)。

   1. 先写一个IDL 文件，包含接口的uuid 和定义
   2. 通过微软的 midl 工具，将IDL 文件生成为 client 和 server 两份代码。IDL 中定义的函数与结构体原型，被 midl 根据 Ndr 协议替换成相应的序列化/反序列化函数，遵循IDL 中接口函数的定义，分别放在 client xxx_c.c 和 server xxx_s.c文件中
   3. client xxx_c.c 将接口函数实现封装成了对NdrClientCallxxx 的调用，文件编进程序后直接使用，server 部分的接口函数，是一堆函数定义，需要开发者实现
   4. server 端操作的入口是一个`RPC_SERVER_INTERFACE`结构体，代表此接口的实现。使用时需要先`RpcServerUseProtseqEp`指定调用的通信协议(比如`ncalrpc/ncacn_ip_tcp`)，再`RpcServerRegisterIf`启用接口，之后通过`RpcServerListen`监听请求
   5. client 端的操作入口是定义的一堆接口函数，内部依赖`MIDL_STUB_DESC`指定接口Uuid 和序列化方法。client 调用接口函数实际发出请求自动调到server 的实现函数，到达server 时所有参数指针都已经反序列化

虽然是跨进程操作，但使用者在调用Rpc 时不用关心指针和数据的传递问题。同时Rpc 支持多种通信方式，Server 端支持自动线程池，支持连接时验证身份，封装的很不错。Windows 本身有许多服务都是 Rpc 形式，比如“服务管理”。我们调用一个`StartService`，实际是通过 sechost.dll 封装的 NdrClientCallxxx 往services.exe 监听的`\RPC Control\ntsvcs` 端口发送了一个Rpc 请求，services 中有相应的模块处理，之后再返回结果。类似的`psexec` 或者 `impacket-wmiexec`是很流行的工具，是连到远程机器135 端口的 RPCSS 服务，发出Rpc 请求

Rpc 的设计思路与 socket 很像，[https://learn.microsoft.com/en-us/windows/win32/rpc/how-rpc-works](https://learn.microsoft.com/en-us/windows/win32/rpc/how-rpc-works)。从开发者的角度出发，可以分为这么几层

1. 最上层 client 看到的是封装好的函数，server 看到的是`RPC_SERVER_INTERFACE`结构体
2. 往下 client 看到的是对 `NdrClientCallxxxx(MIDL_STUB_DESC` ... 的封装
3. 往下是 Binding Handle，Handle 绑定了数据通信协议和发送目标，调用实际发往 Handle。此处Client 使用的协议要与 server 监听对的上
4. 底层是传输层。Rpc 句柄对应的具体传输数据功能。支持的传输协议 [https://learn.microsoft.com/en-us/windows/win32/rpc/protocol-sequence-constants](https://learn.microsoft.com/en-us/windows/win32/rpc/protocol-sequence-constants)

Rpc Server 的接口要提供服务，需要注册与监听。相关的实现在Rpc 的运行库 rpcrt4.dll

1. 本进程注册与监听
   1. 使用`RpcServerUseProtseqEp/Ex`启用进程对外提供的协议和连接点名字Endpoint
      1. 这个函数产生连接点的关键字是 Protseq+Endpoint，如果协议是 `ncalrpc`，Endpoint 名字是 `ntsvc`，对外提供的连接关键字就是 `ncalrpc:[ntsvc]`
      2. 可以定义多个协议和连接点，对于Rpc 来说，连接点是进程范围的
   2. rpcrt4 有一个Rpc 目录，记录本进程已注册Rpc 接口，以接口Uuid 为Key，相当于进程范围的接口目录。使用`RpcServerRegisterIf/Ex`注册
      1. 如果上一步设置有固定的连接点名字，在此创建相应名字的 ALPC端口、Pipe等
      2. 没有设置的，自动创建随机名字连接点，对于ALPC 通信协议创建`LRPC-`加9 位随机数字的端口，对于网络通信协议，绑定随机端口，对于Pipe 随机名字
      3. 随机连接点必须注册全局接口，否则client 找不到，连接点名字是固定的就无所谓了
   3. 注册后可使用`RpcServerListen`开始监听，监听所有连接点
      1. Server 连接处理函数读取Client 请求的接口ID，与Rpc 目录已注册接口进行匹配，已注册的接口可以通过本进程任一连接点接入
2. 全局注册
   1. Windows 使用RPCSS 服务来管理全局的连接点。为此RPCSS.RpcEpMap 导出了 epmap.idl，其中idl client 代码编译在 rpcrt4.dll
   2. windows RPCSS 服务本身是一个Rpc 服务，监听的端口名为`\RPC Control\epmapper`，连接点管理的实现代码在RpcEpMap.dll，监听的网络端口是 135。这个服务提供全局连接点的索引功能，Rpc 服务通过epmap.idl 注册到这里，Rpc Client 到这里找连接点
   3. 注册过程
      1. `rpcrt4!RpcServerInqBindings`获取此时进程对外的连接点，这是要告知RPCSS 的，和接口Uuid 一起传给 `rpcrt4!RpcEpRegister`
      2. `EpRegister`先`BindToEpMapper`连到远程端口`epmapper`，接着call 远程调用`RpcEpMap.ept_insert_ex`，传递接口ID 和连接点信息，RPCSS 收到调用后将接口保存自己的链表中
      3. RPCSS 内部维护一个`IFObjList`的链表，存储注册的接口，以接口 Uuid 为Key。每个接口对象中有个`PSEPlist`存放该接口注册的通信协议和连接点
      4. RpcEpMap 接口描述，[https://learn.microsoft.com/it-it/openspecs/windows_protocols/ms-rpce/10441881-0a7c-403b-8360-5ac961a254fe](https://learn.microsoft.com/it-it/openspecs/windows_protocols/ms-rpce/10441881-0a7c-403b-8360-5ac961a254fe)

Rpc Client 的使用是直接调用 midl 生成好的函数，这里讨论 ClientCall 内部流程

1. 首先序列化传入的参数，变成可跨进程/机器传输的内存块，目的在远程Server 上可以构造一个相同的调用堆栈。序列化需要用到的配置存储在 midl 生成的`MIDL_STUB_DESC`
2. 调用 IDL 中bind 函数的实现，设定连接目标
   1. 通常此处使用的连接点以字符串形式表示，包含协议、主机、名字、安全级别等
      1. 举例 `ncalrpc:myPC[epmapper,Security=Impersonation Dynamic False]`
   2. 通常使用 *BindingCompose+StringBindingFromString* 或*Template+BindingCreate* 创建对应的Binding Handle
   3. Binding Handle 有标志控制是否立即Connect 到连接点
      1. 有固定连接点的此时可以Connect，没有的需要去 epmapper 查询再Connect
3. 目标设置后，调用传输层发数据`NdrSendReceive`
   1. 默认的Binding Handle，在此处Connect 到连接点。没有固定连接点的动态解析，不然没有连接目标，此处通过`rpcrt4!EpResolveEndpoint`自动查询
      1. rpcrt4 中编译了epmap.idl Client 代码
      2. `BindToEpMapper`连接到Binding Handle 指向主机的 RPCSS，主机字段为空则连接到本地。接着以接口Uuid 发出查询请求
      3. RPCSS 进程`RpcEpMap.ept_map`响应请求，先查找接口ID，再查找ID 下对应的连接点列表，匹配Binding Handle 中设置的协议
   2. 实际数据传输形式由Binding Handle 的协议字段指定，协议需要Server 那边在注册时启用
   3. Rpc 请求支持异步`Ndr64AsyncClientCall`，异步可以通过返回`CALL_PENDING` 后续Client 使用API 轮询来实现。也可以在 Client 创建一个新的Rpc Server，让目标Server 完成后主动通知的方式实现
4. 最后收到消息，反序列化结果，回到用户代码

依靠上边的调用机制，Rpc 可以做到call 远程与本地相同的使用体验，这很好的解决了代码复用和功能组织的问题。所有的功能模块不必集中在一个模块或进程，甚至可以在不同的电脑上，使用者需要知道的，只是一些 idl 文件而已。不过因为功能模块不在本进程运行，此时就需要有一套管理机制保证功能的可用性，当需要使用服务时，对应的支持进程应该存在，当不使用时，对应进程应该退出以降低系统负载。

现在如果机器有 2 个服务，那么开机即运行占不了多少资源，如果有 200 个服务，无意义的占用就太多。因此除了一些系统关键服务，其他的服务都应该是按需运行的。对于服务的开启和关闭操作，Windows 做了一套Rpc 放在services.exe 中，连接点`\RPC Control\ntsvcs`。对于功能的动态启用与退出，Windows 增强了 RPCSS

Windows 对于服务的优化，可以借用几个例子svchost.exe、rundll32.exe、dllhost.exe

1. svchost 是服务进程运行环境壳子，在创建服务时，可以设置命令行比如：`%SystemRoot%\system32\svchost.exe -k RPCSS -p`，然后在注册表 `SERVICE\Parameters\ServiceDll` 中指定DLL 路径，这样`sc start`服务时会以 svchost 来装载 DLL 运行，DLL 需要实现基本的服务函数并导出，比如 `ServiceMain`
   - 这个封装可以减少重复的代码编写，且因为共用svchost 的Section 可减少内存占用
   - 在注册表`Windows NT\CurrentVersion\Svchost`中，可以将服务加入某一个组，同组的服务会共用一个svchost 进程，这样可以减少进程数量和内存占用
1. rundll32 是纯粹加载DLL 并调用指定函数的壳子，运行完即退出，算一种动态进程管理
2. dllhost 则是 COM 服务的一种表现形式。COM 服务可以是EXE 也可以是DLL。COM 服务实现了按需启动与闲时退出，是理想的动态服务管理模型
   1. 先以 COM 模型编写DLL/EXE
      1. 定义CLSID，实现`IClassFactory/2/X`。DLL 需要导出`DllGetClassObject`，在其中返回工厂类的对象
      2. 使用 factory 中`CreateInstance`获取 CLSID 实现的类实例，这些结构与普通COM 无差别。后续也一样，通过类实例`QueryInterface`拿到不同的功能接口
   2. 写入注册表配置，给其他程序使用
      1. DLL 模式，`regsvr32`或`DllRegisterServer`将对应的`Class GUID`写入注册表 `HKEY_CLASS_ROOT\CLSID`。支持加载到调用者进程自身空间的，将DLL 路径写子项 `InProcServer32`，可以同时设置支持远程和本地
         1. 支持Rpc 服务的，写入 AppID 的键值信息，并将细节写到`HKCU\AppID`，接口的序列化信息写到`HKCR\Interface`
         2. `HKCR\AppID\?\LocalService`，关联到服务，创建此接口实例时，启动此服务
         3. `HKCR\AppID\?\DllSurrogate`，指定加载此 DLL的壳子，缺省为 dllhost.exe
         4. `HKCR\AppID\?\RemoteServerName`，指定使用远程主机创建接口
      2. EXE 模式，如果工程通过 Visual Studio ATL 创建，自带响应`-RegServer`的命令行写CLSID 注册表，将 EXE 路径写入`LocalServer32`
   3. client 以`CoCreateInstance`创建服务
      1. 本进程加载情况，通过`LoadLibrary`加载注册表中的 DLL 路径到进程自身，通过 `DllGetClassObject`取factory 做后续操作
      2. 非本进程加载的情况，则是由 DcomLaunch 拉起对应服务进程，服务进程启动后监听Rpc 端口，client发出的请求通过Rpc 到此端口，服务进程取factory 做后续操作
      3. 跨机器创建接口，除注册表指定`RemoteServerName`，也可在创建时传入远程机器参数`COSERVERINFO`
         1. 这里与Rpc 不一样的是请求不直接发往远程机器，而是先到达本地RPCSS，之后RPCSS 转发到远程机器上。后续与第2 点行为一致
   4. 引用计数控制服务退出
      1. client 的取得的接口都Release 后，COM Server 将自动退出

COM - *Component Object Model* 加上 Rpc - *Remote Procedure Call* 就是 DCOM - *Distributed Component Object Model*，是 Windows 标准服务模型，COM 负责将功能封装成接口，RPC 则允许功能的实现放在任意位置。DCOM 大量应用在 Windows 系统的组件与功能实现中。考虑到资源占用、权限控制、性能、调用便捷性，这个模型十分适合Windows 功能开发

两个功能的集成以RPC 为主线，RPCSS 中加多一套管理 Class 的数据接口，新接口类型叫 ORPC。之前的 Rpc 调用是以 IDL 定义的接口 Uuid 为Key，而DCOM/ORPC 则需要以COM Class 的 CLSID 为Key，一个 Class 可以提供多个接口，到接口这一层还是继续沿用的Rpc Interface

为管理Class 增加的逻辑

1. 所有进程增加数据
   1. 类管理
      1. 定义`CClassCache`，这个是如果进程加载了 CLSID 对应的`IClassFactory`，都缓存起来。接口可以是`DllGetClassObject` 从DLL 取的，也可以是代码中定义的
      2. 定义`CObjServer`，相当于对Rpc 连接点管理的封装。所有的请求先到达这里，在这个类里面搜索`CClassCache`或主动拉起一些类实例。这个类内置了一个RPC 接口`ISCMLocalActivator`
         1. 定义`gOIDTable`，指定接口实例的ID，其他程序使用ID 来指代本进程的某个接口实例，真正调用到本进程时用来索引实例
      3. 定义`gOXIDTble`，主要跟`CObjServer`相关。进程对外提供的接口想被使用者找到，需要有个标识定位`CObjServer`，光依靠连接点比较单薄，这里定义了`OXID`，包含的信息丰富一点，内部关联到连接点、Class、进程ID 等
   2. 接口管理
      1. 定义`gRIFTbl`，Remote IF Table，对接Rpc 接口定义，使用IDL 定义Rpc 协议时给Client 和Server 生成的代码是固定的，这个相当于动态的
         1. 在Client，表里存放`IID`与`MIDL_STUB_DESC`的映射，Class 管理是新增逻辑，接口这一层复用了Rpc 逻辑
         2. 在COM Server，这个表存放`IID`与`RPC_SERVER_INTERFACE`的映射。COM Server 创建出某个接口后，使用`RpcServerRegisterIfxx`将对应IID 注册到Rpc 目录并存到这个特殊表中
      2. 定义`gIPIDTbl`索引`IPID`与接口实例，接口实例的底层指向`gRIFTbl`的记录
2. RPCSS 增加Class 管理逻辑
   1. 定义`rpcss.ILocalObjectExporter/ISCM/IROT`的RPC 接口，Client 代码编译在combase.dll，提供全局Class 的索引
      - Class 注册的走Exporter，Class 使用的走SCM/Rot
   1. 定义`rpcss.CServerTableEntry`，记录CLSID 与COM Server 的关系。这个主要进程管理，服务状态管理之类
      - 定义`CClassData`，Class 的注册表详细配置信息
   1. 定义 `MachineID`，用来标识 RPC Server 所在的机器
   2. 定义 `OXID`，用来标识服务提供者的`CObjServer`，存放在 `rpcss!gpServerOxidTable`，不再依靠RpcEpMap 查找连接信息
   3. 定义`OBJREF`，表示指定`CObjServer`中的指定接口实例。`OBJREF`强关联`gOXIDTble`中的记录指明`CObjServer`，同时使用`IPID`强关联接口实例
      - `IPID`由接口`IID`和接口实例的`OID`组成，`IID`是固定的，`OID`是每次创建接口时取的本机唯一的，这样可以区分相同的`IID`多次创建的实例
1. 分出 DcomLaunch 管理Server 生命周期
   1. 上边的`rpcss.CServerTableEntry`主要是记录状态的。拉起进程与服务的动作被单独拎出来了，做了个RPC 服务`IActivationKernel`，以DcomLaunch 的服务名启动。功能就是通过CLSID 管理 COM Server 的生命周期，导出接口`\RPC Control\actkernel`
   2. 创建共享Section `Global\__ComCatalogCache__`，管理类`combase!CClassCache`，缓存已注册的Class，并且监听注册表变化
   3. 创建共享Section `Global\RotHintTable`，管理类`rpcss!CScmRot`，缓存已创建的接口实例，也叫`RunningObjectTable`
      - 表里的实例支持设置别名，别名类型为`moniker`，为接口调用提供了多种途径。有别名才能在像PS、VBS 脚本用简单的名字像ProgID 创建对象
   1. RPCSS 使用上述两个Section 数据判断Class 和接口实例的状态
1. COM Server 进程
   1. 本地起`CObjServer`，然后用`ILocalObjectExporter`将CLSID 和OXID 的关系通知给RPCSS，这样Client 去RPCSS 查CLSID 的时候就能找过来了
   2. `CObjServer`里面内置的RPC 服务`ISCMLocalActivator`主要响应RPCSS 发来的创建接口实例请求，其他进程没试过，应该也能请求
      1. MTA 模式`CObjServer`只有一个
      2. STA 模式可以有多个，为了保证STA 线程安全，注册Class 的那条线程需要循环取线程的消息队列，STA 的消息会在队列排队以保持请求是顺序执行的
         1. 这算个不大不小的限制，GUI 进程才有消息队列
      3. `ISCMLocalActivator`本身的实现与本地COM 无差。`CObjServer`找到CLSID 对应的`IClassFactory`取类实例，再`QueryInterface`取接口`IID`对应的指针
         1. 多加的逻辑是取到接口指针后注册到`gRIFTbl`，还要申请一个`OID`与`IID`一起做成`IPID`返给Client
2. RPCSS Client
   - Client 收到的接口实例是`OXID+连接点+IPID`，存入`gOXIDTbl`之后以这个Entry 创建 `OBJREF`，再`Unmarshal`一个供Client 使用的接口指针

看Client 调用 `CoCreateInstanceEx` 创建一个远程的 DCOM 接口实例

> *-- CoCreateInstance*
> *-- client.combase!ICoCreateInstanceEx* <> *ActivatePropertiesIn::DelegateCreateInstance*
> *-- client.combase!CRpcResolver::DelegateActivationToSCM*
> ***-- RPC call ISCM [client → RPCSS]***
   > *-- RPCSS.rpcss!SCMActivatorCreateInstance <> RPCSS.rpcss!CScmActivator::CreateInstance*
   > *-- RPCSS.rpcss!Activation*
   > *-- RPCSS.rpcss!RemoteActivationCall / CServerTableEntry::CallRunningServer*
      > *-- RPCSS.rpcss!CServerTableEntry::StartServerAndWait*
      > *-- RPCSS.rpcss!CClassData::Launchxxxxx*
      > ***-- RPC actkernel [RPCSS → DcomLaunch]***
      > *-- DcomLaunch.rpcss!CreateProcess/StartService*
         > ***-- RPC ntsvcs [DcomLaunch → services.exe]***
         > *-- services!StartService*
            > *-- target.combase!CoRegisterClassObject*
   > ***-- RPC call objsrv [RPCSS → target]***
      > *-- target!CObjServer::CreateInstance <> target!ServerAllocateOxidAndOids*
> \-- client read and parse ISCM result <> Unmarshal
> ***-- DCOM call IUnknown [client → target]***
> *-- client.Marshalxxx (OXID/IPID) + SendReceive*

这个流程可以分成几个大块

- 获取 RPCSS 的 ISCMActivator 接口
- 通过 RPCSS 的 ISCMActivator 拉起 Class 对应的 COM Server
- COM Server 启动后响应 RPCSS 的实例创建操作
- Client 收到结果后构造给用户代码使用的接口指针

逐条看Windows 的实现

1. 获取ISCM

按照最简单的实现，在 Rpc 的基础上，原有的是通过接口Uuid 取连接点，对Class 增加CLSID 取连接点即可。Client 用 CLSID 查连接点，查到后Client 直连COM Server 创建需要的接口

这里可能考虑两个问题，所以创建接口实例并非由Client 直接发往COM Server，而是通过RPCSS 中转。其一是权限检查，统一管理Client 对Class 的访问权限。其二是负载，RPCSS 可以根据请求的数量与频率选择起多个不同的COM Server 处理请求

RPCSS 提供了`ISCMActivator` 的 RPC 接口专门给用户代码创建接口实例，但是这里有个神奇的地方，并没有什么模块编译`ISCMActivator`的 idl client。它没有使用常见的`BindingCompose`和`NdrClientCall`的形式调用此接口，而是以模仿DCOM 的模式先创建一个OXID，再创建`OBJREF`，再`Unmarshal`出接口指针。这里神奇的是没`OID`，如果目标是一个DCOM 服务接口，`OID`是错的应该会导致COM Server 的`gIPIDTbl`中找不到处理请求的对象

不知道是不是所有的RPC Server 接口都可以这样使用，这里看`combase!MakeSCMProxy`

1. 首先在Client 构造一条假的`OXID`记录。`OXID`对应`OXID_INFO`的CLSID、ProcessID、连接点信息全部手动构造
2. 把这条记录当作一条正常返回的接口实例记录，创建一个`OBJREF`对象。其中关联的`IPID`手动构造，`IID` 填`ISCMActivator`，`OID`部分从RPCSS 随便取一个
3. `Unmarshal`这个构造的`OBJREF`得到一个`ISCMActivator`接口指针。接口是构造出来的，虚函数表非常大，全部指向Stubless/ProxyForwarding
4. 调用 `ISCMActivator->CreateInstance`
   1. 调到构造的虚函数表，使用系统自带的`oleaut32!PSOAInterface`对接口进行`Marshal`。把接口写成可传输的 IStream
   2. 发往epmapper
5. RPCSS 在`rpcss.InitializeSCM`时注册了此Rpc 接口，收到消息正常处理
2. 拉起COM Server

请求到达`RPCSS.rpcss.SCMActivatorCreateInstance`，再转到`RPCSS.rpcss!CScmActivator::CreateInstance`，这里先查找CLSID 对应的`CServerTableEntry`，Entry 记录了CLSID 相关的COM Server 状态，比如进程状态、Server 令牌、暂停状态等等。它控制 COM Server 的生命周期，同时提供对 Class 的操作入口 `CServerListEntry::CallServer`

有两种情况更新`CServerTableEntry`，其一是请求时没找到CLSID 对应的记录，需要创建。其二是COM Server 启动后，往RPCSS 更新自己CLSID、连接点等等详细信息

`CallServer`会往COM Server 监听的`ILocalSystemActivator` RPC 接口发送创建请求。这里跟Client 请求`ISCMActivator`的逻辑是一样的，模拟DCOM 的形式构造接口做调用。请求发往 COM Server 的`CObjServer`，`CObjServer`中处理对应的实例创建并绑定`OID/IPID`，结果返回RPCSS 再返回给用户代码，后续用户代码调用接口里面的函数就直接连到COM Server 去做了，只有创建经过RPCSS 的中转

对于不活跃的COM Server，需要自动拉起。比如`CServerTableEntry`中CLSID 对应的COM Server 进程是退出状态。此时RPCSS 将CLSID 发给`DcomLaunch` 进程`actkernel`端口。DcomLaunch 会根据Class 的配置以各种方式将COM Server 拉起来。而RPCSS 要做的就是轮询`ServerTable`，等COM Server 来更新这个表

RPCSS 等待COM Server 启动是一个堵塞等超时的操作，Client 请求Rpc 也是一个堵塞等超时操作，如果COM Server 启动过程有问题，可能导致Client 进程这边出现卡顿，如果逻辑影响到GUI 线程，可能导致出现转圈或程序无响应的现象

3. COM Server 启动后响应 RPCSS 的操作

COM Server 进程启动，如果是 COM DLL 一般是dllhost.exe 拉起，dllhost 对外提供服务，调用`CoRegisterSurrogateEx`。通过`ILocalObjectExporter->ServerAllocateOXIDAndOIDs` 为`CObjServer`申请 OXID，再通过`ServerRegisterClsid`将CLSID 和OXID 更新到RPCSS

EXE 或服务的话，需要主动调用`CoRegisterClassObject`，其中做的事情也是一样的，启用 `CObjServer`，申请OXID，`ServerRegisterClsid`将自己注册到RPCSS。Visual Studio 生成的 ATL 工程，其中ATLModule 会自动做这些事情

COM Server `CObjServer::CreateInstance`处理RPCSS 发来的创建请求，从`CClassCache`查找CLSID 对应的`IClassFactory`，接着factory->CreateInstance 创建类实例，从类实例 Query 需要的接口IID。接口实例还需`Marshal` 成可供外部使用的状态 `CoMarshalInterface`，找序列化代码，注册Remote IF Table，加入`gIPIDTbl`

4. Client 收到结果后构造给用户代码使用的接口指针

对于Client 来说，创建实例的结果关键部分由`OXID+连接点+IPID`组成，Client 侧通过这些信息构造远程指针。构造过程与`combase!MakeSCMProxy`一样，其后行为也是 Stubless/Proxy 到远程Server，有所不同的是此次的数据是RPCSS 真实返回的

这里一直没有讨论到具体的Marshal 如何完成，通常我们把接口指针变成可传输的`IStream`内存块，叫做`Marshal`，反过来叫`Unmarshal`

Client 收到`OXID/IPID`后，在本地`gOXIDTbl`生成一条记录，并以此生成一个`OBJREF`，这一步可以让我们找到COM Server。接着需要生成`gRIFTbl`中的`MIDL_STUB_DESC`，这样才能基于Rpc 通信。其后将对象保存在`gIPIDTbl`中后续使用

Client 侧类`MIDL_STUB_DESC`的东西叫`Proxy`，封装成了一个`IRpcProxyBuffer` 的结构。通常创建这个结构需要用到`IPSFactoryBuffer`，这个PSBuffer 就是当时Rpc 架构中 midl 生成的那一堆序列化代码。绕回来了，这一坨代码是少不了的。使用Visual Studio 创建 ATL 工程时有个配置`"Allow merging stub/proxy code"`，选择不合并，会多生成一个 PS DLL 工程，这个工程专门编译 midl 生成的那坨代码，对外`DllGetClassObject`时导出PSBuffer

所以流程变成，COM Server 生成接口实例时加载PS DLL，通过PSBuffer 拿一个 `RPC_SERVER_INTERFACE` 去 `RpcServerRegisterIf`。Client 需要接口调用时通过PSBuffer 拿一个`MIDL_STUB_DESC` 去`NdrClientCall`。再给这个PS DLL 做个注册表键值`HKCR\Interface\?\ProxyStubClsid32`说明文件位置

因为框架上很多代码是重复的，这里做了一些优化。Visual Studio 配置上选择合并时，不会额外再生成一个PS 工程。而是使用Windows 内置的两个通用`PSFactory`代替

1. `oleaut32!PSDispatch {00020420-0000-0000-C000-000000000046}`，这个实现支持 `IDispatch` 接口，Windows 内部可以通过脚本使用的接口都继承`IDispatch`
2. `oleaut32!PSOAInterface {00020424-0000-0000-C000-000000000046}`，这个是通用的实现，都可以指定为这个

系统DLL 提供的2 个`IPSFactoryBuffer`把通用的框架定义了，实际在处理参数序列化的时候还需要参数的类型信息，这个模式下类型信息被独立出来放到了`TypeLib`，`HKCR\Interface\?\TypeLib`。在取Stub 和Proxy 时，oleaut32 会`LoadTypeInfoEx`打开文件查找TypeLib 资源并将类型信息读进来。Visual Studio 编译一般存放在COM Server EXE/DLL 里面。其实本质还是没有变化的，包括将TypeLib 存成 olb/tlb 等格式，Client 和Server 都离不开 midl 那一坨

使用 Visual Studio 开发COM Server，配置也比较繁琐，增加Class要遵循`"Add"->"New Item"`->"`ATL Simple Object`"。增加接口的函数最好不要手动编辑项目中的 idl 文件，而选择工程的 `"Class View"`，右键接口->"`Add Method`" 让Visual Studio 去更新。而默认如果选择生成PS 工程时，编译配置要调整PS 工程的 linker include 的路径，否则会提示找不到 dlldata.c 和 xxx.def

在上述DCOM 机制下，Windows 构建了各类系统功能与服务组件。打开任务管理器，我们能看到 services.exe 下，有很多的 svchost.exe，其中前两个是`DcomLaunch`服务和`RPCSS`服务，这是COM 服务管理的基础

`DcomLaunch`下的子进程可以认为都是为`CoCreateInstance`提供功能而创建的，是指定为 `LocalServer32`和`DllSurrogate` 类型的服务。一般都会监听一个 OLE 开头的 LPC 端口，因为DCOM 默认实现异步的方式选择了Client 创建Server 等COM Server 主动通知

services.exe 下其他 svchost 中，监听类别比较杂，有些是为了响应系统的某些通知，所以它可能什么也不监听。有些是 IDL 定义的Rpc 服务，这些服务有的会写死连接点，有的不写死，没有写死的那部分就会监听以 LRPC- 开头的随机端口。还有部分是 COM Server 中以 `LocalService` 运行的，这部分它可能既有支持 COM 实现的 OLE 端口，也有自己注册的 LRPC-。而且svchost 是可以承载多个服务模块的，这使得 svchost 监听的内容很杂。

由于它内部的不透明与复杂性，让很多开发者并没有将 RPC/DCOM 作为服务和组件开发的首选，Windows 对于这个设计的实现复杂度过高了，如果开发者使用，出现问题时因为不透明，调试起来比较麻烦。但是如果微软能够更多的消除这种不透明与复杂性，或许大家开发的程序可以有更好的性能和稳定性，这其实是一种双赢

### ETW

在 ida Windows 模块时，随处可见类似 WPP_XXX 或 WmiTraceMessage 类似调用，有必要探讨下，这是Windows 提供的日志系统，很好的设计，这个特性也是比较模糊的

我们一般程序打日志，可能一般都打到文件中，文件日志有一些缺点，比如程序崩溃时，大概率文件缓存中的内容会丢失，其次日志路径和日志级别不方便动态配置，还有就是性能损失。etw 是一段Windows 提供的缓冲区，内存形式，速度很快，写日志和读取分离，日志级别与日志开关可以动态配置，使用也很方便

Etw 要用起来可以分成 2 个部分

1. 写日志的提供者 Provider，就是正常需要记录日志的进程
2. 读日志的 Consumer，类似 log viewer 这类

严格分，还可以分出一个控制某个日志开启、关闭的管理部分，一般跟 log viewer 放一起。使用的流程大概这样：

1. 日志提供者这边需要先 Event/EtwRegister 注册一个 UUID 到系统的日志提供列表，作为日志的 ID，后续操作开启关闭都用这个
   1. 然后就可以 TraceEvent/TraceMessage 开始正常在代码中写日志
   2. 要真正写到 etw 缓冲区里，需要管理部分开启这个ID
2. Consumer 这边传递一个Data Callback 到 ProcessTrace API，等待回调输出日志
3. EnableTrace 开启日志ID 去控制Provider/Consumer

Windows Event Viewer 展示了大多数Windows 自己注册的Etw 日志提供者，“Applications And Service Logs“ 分类菜单下边的日志还可以右键对日志动态开启关闭。除 Event Viewer，WDK 中的 traceview.exe 提供的日志更丰富。Google 也有一些读写 etw 的开源工程。

Windows对 Etw 的使用做了更高一层的封装，[https://learn.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest](https://learn.microsoft.com/en-us/windows/win32/wes/writing-an-instrumentation-manifest)。这套封装比较难用，直接用 API 会好点

提到 Etw 就绕不开 Etw Hook。以早期的流程举例

在打印日志内容时我们经常避免不了的需要输出时间，而如果将时间以较细的颗粒采集，我们就可以使用它做为性能监控工具使用。`Windows Performance Toolkit`，就是采集 etw 的输出，统计、分析性能。Etw 深入到了 Windows 的方方面面，在 syscall、内存管理、Cpu 调度等地方都有性能统计需求。ntoskrnl 中可以 ida-x EtwWrite，这是写日志相关的函数与其调用，预置的性能监控相关的可以搜索 PerfInfoLogXXXX 相关函数

管理部分StartTrace 开启日志时，可以传入一个 `EVENT_TRACE_PROPERTIES`，告诉系统需要启用什么日志ID、日志记录模式、记录时间精度等等。其中`PROPERTIES.Wnode.ClientContext` 就是日志时间格式的精度，在R3 下这是个 DWORD 值相当于枚举。进入 R0 `EtwpStartTrace`，系统根据 `EVENT_TRACE_PROPERTY` 生成一个新结构体 `_WMI_LOGGER_CONTEXT`，其中`_WMI_LOGGER_CONTEXT.GetCpuClock`这个指针会根据不同时间精度指向不同的时间获取函数，每次写日志时都调用这个指针获取时间

自然而然会想到替换这个指针

通过`PerfInfoLogSysCallEntry`可以看到，只有`EtwpHostSiloState.EtwpLoggerContext[]`前边两个 Logger 会记录syscall 事件

1. 系统启动阶段调用 `ntoskrnl!EtwInitialize`，其中初始化一个重要的结构体 `(_ETW_SILODRIVERSTATE)ntoskrnl!EtwpHostSiloState`。这个结构体主要管理系统注册的一堆日志Provider
2. `EtwpHostSiloState.EtwpLoggerContext`是一个 `_WMI_LOGGER_CONTEXT` 的数组，前边 2 项被保留为 `CKCLGuid` 和 `SystemTraceControlGuid`，对应 "Circular Kernel Context Logger" 和 "NT Kernel Logger"，这两个Provider 记录内核日志

那么Hook 的逻辑就清晰了，开启内核Log，找到对应的`WMI_LOGGER_CONTEXT.GetCpuClock`，替换成自己的Hook 函数。Etw Hook 通过先启动内核 Logger，然后 特征码/PDB Symbol/offset 等方式，在内核下定位到 CKCL 或 SystemTrace 的 `EtwpLoggerContext.GetCpuClock`，替换成自己定义的函数。这样每次发生 syscall 获取时间，就进入 Hook 代码了

随着使用这类 Hook 的应用增加，Windows 已经多次调整这块的逻辑，Etw Hook 相对应的也升级了好几次。Hook 主要宗旨还是在`EtwpLogKernelEvent`函数逻辑中寻找可替换的函数指针并构造触发条件，大多落在获取时间这块的逻辑上

Etw Log 是很好的日志与性能分析系统，应该多使用。Etw Hook 不是一个正确的 Hook 点，定位指针本身就有风险，其次开着 syscall 日志也影响机器性能，商业产品不应该使用

### APC与中断

在 LdrInitialize 加载完所有模块，转到 `RtlUserThreadStart` 之前，主线程会 Call 一次 `ZwTestAlert`。函数内会做一次当前线程 APC 队列`ETHREAD.ApcState.ApcListHead`的检查，这个函数只检查UserMode 链表，如果链表不为空，设置线程的标记`ApcState.UserApcPending/All`。User Apc 的触发相比Kernel Apc 时机较少，可以ida 看 `KiInitiateUserApc` 的引用。最常触发的位置应该是`KiSystemServiceExit`，然后是`NtContinue`。`ZwTestAlert`的设计，是刚好是一个内核调用，返回用户代码前如果有用户Apc 必然先执行

APC 在这里是一种改变Cpu 执行流程的方法，因为Cpu 是无状态的，只会一直往前运行，提到改变流程，就需要先说到中断。中断是Cpu 的机制，用来打断当前代码直接跳到新地方执行

**IDT**

Windows 通过 IDT 管理中断的行为。在系统启动初期，将基础的 IDT 项 `ntoskrnl!KiInterruptInitTable`挂到Cpu 的控制结构`KPCR->IdtBase`。其他的硬件驱动通过 `ntoskrnl!IoConnectInterrupt` 把自己的中断挂上去，中断是`PKINTERRUPT` 结构，定义了中断号、处理函数、处理函数的`SynchronizeIrql`。中断发生时 Cpu 根据中断号执行对应的`KPCR->IdtBase[x].DispatchCode`，这些Code 执行时内部会提升到`SynchronizeIrql`并调用预定义的处理函数，这些预定义的处理函数叫`ISR` Interrupt Service Routine

**APIC**

Windows 是抢占式操作系统，中断发生时，Cpu 会立即跳到中断处理函数执行，正在运行的代码可能随时被其他代码打断。为了保证中断执行的完整性，中断设置了级别。即当前运行代码的中断级别如果大于等于新发生的，则将新发生的中断排队，等当前代码跑完再提交。在 intel 8086 中断的介绍中[https://pdos.csail.mit.edu/6.828/2012/readings/hardware/8259A.pdf](https://pdos.csail.mit.edu/6.828/2012/readings/hardware/8259A.pdf)，中断管理由APIC 模块负责，对外导出了多个寄存器。中断处理逻辑有IRR 接收请求、Priority Resolver 优先级管理、ISR 提交处理。硬件信号到达IRR 后排队，由优先级管理决定是提交还是等待。在`HalpInitializeInterrupts` 中，Windows 内核定义了2 个由内核代码发起的中断，并模拟了一个类似APIC 的中断控制器，有多种实现，可以提交到真实的APIC IRR 沿用已有逻辑，也可以自己维护一个队列触发 IDT

**IRQL**

中断级别表示为 IRQL `Interrupt Request Level`，APIC 有一个TPR 寄存器表示当前Cpu 正在运行的IRQL，读写IRQL 通常通过 `readcr8/writecr8` 指令。x64 上有16 个级别(0-15)，通常情况下，我们用到的就是 DISPATCH_LEVEL、APC_LEVEL、PASSIVE_LEVEL，就是 0-2 软中断。更高的3-11 是DIRQL 给硬件设备用的。12-15 是硬件间同步与管理，比如Cpu 缓存同步、电源事件、蓝屏请求等。在中断处理的过程中，有时低IRQL 的处理函数在执行多个有关联的指令时，通常不希望被其他中断打断，Cpu 在这里拆分了硬件中断INTR 和 NMI，提供了`cli/sti` 指令用来屏蔽/恢复INTR 中断，屏蔽期间 INTR 会被丢弃。屏蔽功能内置在APIC 中，不影响内核模拟的2 个中断

**DPC**

因为IRQL 的抢占设计，高IRQL 的请求都被要求在极短时间完成，以免把整个系统卡住，当需要更多执行时间时，Windows 提供了DISPATCH_LEVEL 的队列 `KPRCB->DpcData`，这个队列用来给高IRQL 的操作降级。以典型的时钟中断举例，通常来说主板上的时钟发生器每10ms 往APIC 发送一次时钟中断，中断同步 IRQL 是13 `CLOCK_LEVEL`，中断处理函数是 `HalpTimerClockInterrupt`，处理任务主要是 `KiUpdateRunTime`。里面会更新线程已运行时间，如果时间片到期，设置到期标志并发送软中断告知Cpu 做线程切换。另一个检查`KPRCB->DpcData` 列表和内核定时器，在自身的IRQL 下不做耗时操作，使用队列+软中断触发的形式。搜索`KiInsertQueueDpc` 可以看设备驱动中分发函数具体实现大多是Queue 到DpcData 队列

中断发生时`SAVE_TRAP_STATE`/`RESTORE_TRAP_STATE`虽然不像线程切换开销那么大，但也是有开销的。时钟中断触发频率降低可以减少中断次数，每次分配的时间片延长可以减少线程切换的次数，好处是可以提升系统的性能，负面的影响是会增加用户操作的延迟，时间片与时钟中断频率都不是固定的，Server 和普通桌面版本这些值的设定是不同的

事实上随着操作系统性能的更多要求，DPC 也不能占用很多时间。因为IRQL 只有0-2 是软件能够控制的，像上边的时钟中断的处理，Windows 使用DISPATCH 中断实现时间片到期切换线程的逻辑，用以支持多任务处理。根据IRQL 抢占的规则，这会形成一个现象，谁处于 DISPATCH LEVEL 谁就可以一直运行，因为时间片到期切换命令是一个普通的DPC Interrupt，要等当前Cpu 降到DPC 以下才会触发。为了不影响系统整体的性能和响应，在DISPATCH 下的耗时操作，就需要提交APC 请求

**DPC的限制**

Dpc中不允许`SwapContext`

Dpc通常在DISPATCH 中断的上下文中执行，而DISPATCH 中断的触发只要IRQL<2 即可，这使得Dpc的响应非常快，但同样的，这导致Dpc 执行时，当下运行在Cpu 上的这条线程其数据状态、锁状态变得未知。执行中断时`SAVE_TRAP_STATE` 保存当下内核栈Context，中断完成`RESTORE_TRAP_STATE`

Dpc中执行切换要考虑几个问题

- 其一是新线程是否会修改原线程的数据产生数据损坏问题
- 其二假如新线程要获取Dpc 或原线程占用的自旋锁，而自旋锁是不停的访问变量，这里会把Cpu 卡死
- 其三硬件中断本就需尽快完成，切出去先执行其他线程可能导致逻辑混乱，比如网络包到达Dpc，数据写到一半切到读包逻辑，这很危险

在这个条件下，Dpc的执行禁止`SwapContext`切换线程，并在`SwapContext`中做了校验，如果从DpcRoutine 调用过来就蓝屏`ATTEMPTED_SWITCH_FROM_DPC`

这个结论可以扩展到`DISPATCH_LEVEL`，通常处于这个IRQL，或者是因为正运行Dpc，或者是调用链中有函数正在占用`KSPIN_LOCK`，这两种情况下`SwapContext` 都很危险，新旧线程的逻辑会不会产生冲突，行为是未知的

**APC**

APC 的队列与Dpc 不同，Dpc 挂靠Cpu 核心放在`KPRCB` 中，纯内核的逻辑，执行时不关心当前线程。APC 本身不影响任务切换逻辑，数据放在线程结构体中，执行时需要线程环境。APC 最典型的应用是 I/O 相关操作，比如`IopCompleteRequest`，插APC 实现异步读写。提交Apc 请求使用`KeInsertQueueApc`，请求会放到`ETHREAD.ApcState->ApcListHead`，如果需要尽快触发，可以发一个APC 中断

I/O 操作通常涉及大量的等待，等待时必须将其他工作线程运行起来，否则等KEVENT 时没有代码改变KEVENT 的状态等了也没用，这里引出了陷阱的概念，用来主动放弃当前时间片而非等待到期，Windows在各种等待和队列操作的API 中内置了陷阱逻辑

APC 因为其合适的IRQL 在内核中大量使用，比如典型的线程暂停、设置线程Context。但有时代码中正在修改敏感数据时，比如`IopQueueThreadIrp` 将IRP 挂到线程`IrpList`，最好不要发生线程内容的修改，此时可以选择提升到 APC_LEVEL 也可以选择暂时不执行队列中的APC

- ETHREAD 增加了2 个标志`SpecialApcDisable/KernelApcDisable`，Windows 将只有 `KernelRoutine` 的`KernelMode Apc` 称为特殊内核APC，这类Apc 都是在 APC_LEVEL 执行，不能被APC 中断请求打断。`KernelMode Apc` 的 `NormalRoutine` 是降到PASSIVE 执行的，称为普通内核Apc。用户模式Apc 与KernelMode 主要区别是触发时机不同，用户模式需要用户态的调用栈，所以总是在syscall 或R3 中断返回前这些地方执行
   - ApcDisable 的两个标记是包含关系，Special 禁用时所有Apc 不触发。修改线程相关的内容比如获取锁之类，需要先禁用普通内核Apc，否则如果触发Suspend Apc 数据会乱
- 更直接的是`ExAcquireFastMutex` ，它会提到APC_LEVEL，所以这个API 的使用还是需要注意的，常规的锁还是更推荐`ERESOURCE+KernelApcDisable`

在APC 或PASSIVE 进行`SwapContext`是安全的。使用自旋锁会提升到 DISPATCH_LEVEL，它的实现是休眠或不停检查，不会进入线程调度，而`ERESOURCE/FAST_MUTEX/PUSH_LOCK`会进入等待调度逻辑，如果需要在DISPATCH 访问这些锁，最好还是Queue Apc 或者WorkerQueue。在APC 下切换线程时可以保证即使原线程拿着锁，也不会是自旋锁，而是可以调度的，这样新线程获取锁不会把Cpu 卡死，而是可以进入等待再次Swap 回原线程

**PASSIVE**

因为许多内核功能的实现使用`Special Kernel APC`占用APC_LEVEL，所以对于用户代码来说，真正安全的只有PASSIVE LEVEL。为此Windows 内核提供了 `IoWorkerQueue/ExWorkerQueue` 等多个工作队列，同时为Queue 进来的任务设置请求的优先级，起线程池 `ExpWorkerThread` 去执行请求。当用户代码处于APC_LEVEL 需要 PASSIVE 的环境执行任务时，优先使用 WorkQueue

Windows 默认创建的线程都是PASSIVE 的

回到`ZwTestAlert`，这里通常是各大EDR 与杀软比较喜欢的DLL 注入位置，只需要在进程创建回调构造一个用户Apc，插入到主线程，那么Apc 会在`ZwTestAlert`被调用，此时还未到PE 的 EntryPoint，但导入表各个模块已经加载完毕，做 Hook 比较安全，注入过早还需要考虑是否有函数可用的问题。另一个Apc 不涉及 shellcode 或 thread context 的修改，比较稳定

APC 和DPC 都可以将过程分为提交和触发执行两步，APC 的提交队列是线程的`ApcListHead`，提交的函数是`Ke/KiInsertQueueApc`，DPC的提交队列是Cpu 的`KPRCB->DpcData`，提交的函数是`Ke/KiInsertQueueDpc`，提交的过程比较统一，但是触发比较分散，依赖于流程控制，流程控制包含中断、线程时间片、Cpu Idle 线程和主动陷阱

1. 中断控制
   1. 使用`HalRequestSoftwareInterrupt` 发出一个DISPATCH 的中断。Cpu 运行在DISPATCH 以下时，执行`KiDpcInterrupt`，其中主要处理函数为`KiDispatchInterrupt`
      1. 函数中首先处理`KPRCB->DpcData`，如果存在排队的Dpc 请求优先执行，这里只处理 `DPC_NORMAL`
         1. `DpcData[DPC_THREADED]`由IRQL 2 的系统线程池`KiExecuteDpc`执行，使用`ThreadDpcEnable`的标记来控制，开启时对当前Cpu 的Dpc Queue 操作都放到THREADED队列
         2. 用线程执行看起来是为了减少一些Dpc 中断
      2. 接着处理线程时间片到期，这也是为什么时钟中断里面时间片到期发送DPC 中断即可，而不需要Queue Dpc 函数。到期的线程重新提交到`DeferredReadyListHead`，且由于这条线程已经完整的得到过一个时间片，针对`Priority 16`以下的，这里降它的优先级免得下次取线程还是它，最低不低于进程的Priority，新线程取好后`KiSwapContext` 将Cpu Context 换到新线程
         1. 也可能其他逻辑已经算好了`NextThread`，这里就不用算了，直接切换
         2. 为什么DISPATCH 中断里面可以`SwapContext`，这是因为中断发生时，目标线程必然执行在IRQL 2 以下否则中断无法触发
         3. APC是跟着线程走的，所有线程执行到`SwapContext`保存线程状态，接着恢复出新线程，新线程的执行相当于从`SwapContext`函数返回，继续执行，返回前会判断是否`KernelApcPending`，是的话主动发出一个APC 中断
   2. Cpu 当前在APC_LEVEL 以下时触发APC 中断，执行IRQL 1，处理函数主要是`KiDeliverApc`
      1. 内核只执行`ApcListHead[KernelMode]`
      2. `sysret/iretq/sysexit/NtContinue` 这种共享的Trap 代码在返回R3 前，会检查线程的`UserApcPending` 标记，如果存在标记再执行`ApcListHead[UserMode]`，`KernelRoutine`部分就直接执行，`NormalRoutine` 的部分构造一个栈帧通过返回指令跳到`KeUserApcDispatcher` 执行
      3. ApcPending 标记`InsertQueueApc` 时会设置，`xxxTestAlert`类型函数也会更新
2. 线程时间片控制
   1. 线程在`DeferredReadyListHead`被换到Cpu 前要先给时间片，计数由时钟中断来更新，时间片到期后，时钟中断处理函数发出DPC 中断，这回到上边的中断处理逻辑
   2. 如果Cpu 一直运行在DISPATCH_LEVEL，DPC中断一直得不到响应，当前线程就换不出去
3. Cpu Idle 逻辑
   1. 每个`KPRCB` 都有`KiIdleLoop` 线程，当没有新线程需要调度时就执行Idle。跟Dpc 中断响应逻辑差不多，检查DpcData，检查时间片。额外的做些电源省电相关事情
4. 主动陷阱，主要是线程切换
   1. Apc绑在线程上，主动触发的场景主要依靠APC 中断，被动触发是线程切换，线程每次获得执行机会开头就是检查`KernelApcPending`
   2. Windows 在很多常用函数的尾部都调用了`KiExitDispatcher`，这个函数是典型的陷阱调度函数。函数中会处理`KPRCB->DeferredReadyListHead`，重新组织当前Cpu 上的线程优先级，将线程根据优先级排入`ReadyList`或设置`NextThread`，如果算出来优先执行的线程与本线程不同，此时IRQL<2 直接线程切换到新线程，IRQL>=2 则发送DISPATCH 中断利用中断逻辑切换。如果重新组织后还是本线程，则什么都不用做
   3. `KeDelay/NtYield/Wait`等待相关函数，等待会将当前线程挂到`KPRCB->WaitListHead`，再`KiSwapThread`把当前线程暂存，换到其他线程执行。可以等待的对象都有DISPATCHER 头，其中有链表挂着等它的线程，在其他线程中对目标进行比如`KeSetEvent`，函数内部将链表中等它的线程重新挂到`DeferredReadyListHead`
   4. 还有两个主要给PASSIVE直接执行Apc
      1. 在`KeInsertQueueApc`时，加入到`ApcListHead` 后根据不同情形选择将目标线程放入 `DeferredReadyListHead`或者发出APC 中断。对于插入到当前线程的Apc 且IRQL==PASSIVE 时，Insert 这里就触发执行了
      2. `KiCheckForKernelApcDelivery`，在PASSIVE 下直接调用`KiDeliverApc`，高于这个则发送APC 中断。因为`EnterXXXXRegion` 限制了APC 的执行，`LeaveCriticalRegion/GuardedRegion`结尾使用这个函数避免Apc 等太久
   + 部分关联函数

```other
KiExitDispatcher - 通知相关函数、插入队列、释放锁，尾部调用
    ExQueueWorkItemXX
    IoSetIoCompletionXX / IofCompleteRequest
    ExReleaseResource
    KeAlertThread / KeResumeThread / KeSuspendThread
    KeInsertQueueApc / KeInsertQueue / KeInsertQueueEx
    KeRegisterObjectDpc
    KeSetEvent / KiSetTimerEx
    KiContinueEx 
所有等待相关的函数
    KeDelayExecutionThread / KeWaitForXXXX / ...

KeYieldProcessorEx由pause指令实现，让Cpu 休眠几个Cycle，纯等待
```

在IRQL 中有一个经典问题。假如当前线程是 DISPATCH LEVEL，访问了一个被 Swap 到 Paging File 的内存，触发缺页异常，Cpu 转到异常处理函数运行`KiPageFault`，正常情况下，这会导致出现一个蓝屏。这个蓝屏是设计如此的，可以想象一下如果不蓝屏的后续处理

如果这个`NonPagedPool`内存是换出状态，按预期，在处理函数中，需要读取 Paging File 把交换出去的页面读回内存，但文件读取是异步 Irp 操作，里面会有大量等待，等待需要切线程，按IRQL和Dpc 的限制，被动方式切线程的DISPATCH 中断不会响应，主动陷阱的SwapContext 非常危险，预期行为未知。即使能切，文件系统的设计是低IRQL 的，以DISPATCH 发送 IRP_MJ_CREATE 经过文件系统设备栈里的驱动都得挂

此时蓝屏就是最好的选择，可以尽可能保护数据不被损坏，这里不蓝再往下走还是要蓝或者卡死。Windows 在 `KiPageFault`做了判断，DISPATCH 访问分页直接 BugCheck `IN_PAGE_ERROR`，换成蓝屏Code `IRQL_NOT_LESS...`。在时钟中断也做了判断，为了避免Cpu 一直处于DISPATCH，DpcRoutine 执行时间太长时`DPC_WATCHDOG_VIOLATION`

正常的编码与设计中，需要好好规划一下各类代码需要的IRQL，不能改其他模块call 到自己的IRQL

可以看一些常见蓝屏 Code

> *"IRQL_NOT_LESS_OR_EQUAL"*

> 这个 Code 最容易发生的场景，就是在 DISPATCH 下访问了一个分页地址或者已释放的指针。分页地址可能被内核换到 Paging File 里面了，此时访问会跳到缺页中断。*MmAccessFault* 先判断当前 IRQL 是否大于 APC，如果是直接返回 STATUS_IN_PAGE_ERROR，不会再继续往下走了，错误码经过转化就变成 KeBugCheck 的这个 Code。

> *"PAGE_FAULT_IN_NONPAGED_AREA"*

> 内存无效，无效指的是 *PTE.Hardware* 位为0，没有关联到物理内存。或地址格式错误，大概率使用了释放后的指针

> *"MEMORY_MANAGEMENT" 还有个 "BAD_POOL_HEADER"*

> 大概率是用了错误的结构体读写内核数据，或者写越界，导致损坏了原有数据上的一些管理结构，比如 Lookaside list 的Header、Object Header 等等。有些是结构体对齐数的问题，有些是搞错了数据类型

> *"SYSTEM_SERVICE_EXCEPTION"*

> 驱动写的响应IRP 的 DeviceIO 函数出了问题

> *"APC_INDEX_MISMATCH"*

> 退出内核调用前，APC 禁用次数没有持平。最常见的就是忘了 *KeLeaveCriticalRegion*。每次 KeEnterCriticalRegion，KernelApcDisabled 就自增，Leave时自减，SpecialApcDisabled关联到 KeEnterGuardedRegion，道理一样。跟堆栈平衡有点像，进入内核前 Apc 计数与退出时的 Apc 计数应该保持一致。有些 Windows API 要成对使用的，某些API 里面改过计数的，可能也会触发这个问题，比如 KeStackAttachProcess

**规范编码**

不过很好的遵守编码规范与官方限制所开发的驱动有时也会蓝屏或者不工作，大多数情况是跟用户机器环境强相关。许多内核驱动陷入一种无法相信其他驱动的窘境，会在自己的模块中写很多防御性代码。在微软官方定义的文件系统驱动权重中，描述了各类驱动的加载次序，有些厂商会将权重设为超出定义范围的高，然后bypass 所有人。理论在IRP 传递中，如果修改了`TopLevelIRP`，完成后应该设回原值，但这个操作其他驱动不一定会做，依靠这个标记可能导致代码重入。IRP 传递时或者系统回调调用时，前边驱动可能改 IRQL 或带着锁往后 call，导致后面驱动一些API 异常或卡死。还有些代码call 到自己回调时，系统对象里面的内容被前一个驱动修改了，照着官方文档解析的话很容易猝死。都不走寻常路

NT 是大内核，模块间互相影响非常大。事实上 3大主流操作系统都是大内核，微内核的定义大概是只保留Cpu 调度、内存管理、硬件接口，也有说把内存管理也拿出来。不管怎么定义，至少文件系统、设备驱动、进程管理要做成独立进程放R3 执行，中间用消息机制通信。微内核可以让功能模块之间独立，模块之间没有强作用力，调用模块的中断状态、锁状态、内存状态不影响被调用模块，模块出现的问题影响在模块之内，以此提高系统的稳定性。但是它不好的地方是性能开销，一个 API 内部可能产生几十次调用，每个调用都通过消息传递代价太高，做消息内存复制、Context 切换、缓存刷新，对比在一个线程上下文直接调用，差距太大。如果能解决性能问题，相信 Windows 会强推 UMDF，osx 会将 bsd 挪到 R3

在大内核模式下，内存、锁、IRQL 是全局影响的，一个模块出问题，或修改了非自有的内存，或非自有线程的IRQL，都有可能导致其他模块出错，整体有连锁反应，为了尽可能减少这种冲突，应当尽力规范自己的代码

## 进入 AddressOfEntryPoint

到达程序的入口点，不过一般来讲，程序入口点默认不是 Main 函数，而是 PE 结构中的 AddressOfEntryPoint，编译器还要套一层，这是PE 代码执行的起点。

一个比较典型的入口点代码如下：

```other
void start() {
  _security_init_cookie();
  _tmainCRTStartup();
    initterm()
    main()

或者带seh 版本的，Crt给你try 一下子
  _security_init_cookie();
  _scrt_common_main_seh();
    __try
      main();
    __except
  ...
```

程序在初始化时生成 security_cookie，在函数调用初期将 rsp 的值异或一次存起来，在函数退出前取 rsp 的值异或一次与开始的做对比，以此检测堆栈是否平衡，可以用来检测溢出。

### SEH

现在一般都会选择编译带 SEH 的，SEH 是 Windows 处理异常的一种流程。

当程序发生异常时，比如访问一个已经被释放的指针，首先是触发 Cpu _KiPageFault 中断查页表，看看是不是Prototype 页面或者置换到Page file，如果都不是，call `ntoskrnl!KiDispatchException` 处理，也有些异常直接进的比如 除0，比如断点。

异常处理部分：

1. KernelMode
   - 先查找内核调试器，再查找 try/catch 链，无处理时直接 KeBugCheck
1. UserMode
   - 也先查找 KernelDebugger，没有再查找 DebugPort，无处理时转到 R3 `ntdll!Ke/KiUserExceptionDispatcher` 交给用户态
   - 用户态内部主要处理函数是 `ntdll!RtlDispatchException`
      - 先 call `ntdll!RtlpCallVectoredHandlers` 查找进程是否有 VEH 处理函数
         - 需要注意的是，检查的早，即使正常 try，VEH 函数也会进入，所以正常只关心第二次异常的
      - 如果没有，查找线程的 `TEB.NtTib.ExceptionList` 异常处理链看对应 Rip 是否有设置处理函数，每进入一个带异常处理的函数，ExceptionList 就会挂上对应的处理函数
         - 有处理函数就修复、构造堆栈以及各个变量，然后调用处理函数
         - 典型处理函数 _c_specific_handler/CxxFrameHandler，处理函数的功能通常是找到异常代码对应的 catch/except 块，然后转到 except 执行
         - ExceptionList 开头第一个，叫做顶级异常处理函数，就是LDR 初始化的时候`ntdll!RtlUserThreadStart` 的那个 __try，它对应的 __except 函数中会调到用户手动设置的 *SetUnhandledExceptionFilter* 回调函数。这个点处理相对靠后。

            > RtlUserThreadStart:
            > __try
            > Run()
            > __except {
               > ntdll!RtlpUnhandledExceptionFilter == kernelbase!UnhandledExceptionFilter
               > → kernelbase!BasepCurrentTopLevelFilter == 用户设置的 SEH Handler
            > }

      - 如果走完一套没有被处理，再重新以 `STATUS_NONCONTINUABLE_EXCEPTION` 进入内核，内核将异常信息发给 ExceptionPort，就是 csrss 给设置的那个，异常处理流程退出。

通常 ExceptionPort 由 csrss.exe 在处理进程创建通知消息时，给目标进程设置，ApiPort 那个端口。csrss.exe 收到异常消息后，根据系统的错误处理配置，比如通过 wermgr.exe 服务拉起 werfault.exe 进程dump 发生异常的进程，生成错误报告，或者只是弹出一个错误消息框，csrss 最后会结束进程。

异常处理是一个加逻辑比较隐蔽的地方。比如在目标进程中，先设置一个 VEH/SEH，再通过改关键地址的页面属性为 PAGE_GUARD 触发异常到自己的处理函数，要比修改字节码隐蔽的多。

异常处理流程很长，是比较消耗资源的，还是尽量少触发一些异常比较好。

`SetUnhandledExceptionFilter` 函数设置 `KernelBase!BasepCurrentTopLevelFilter`，属于进程范围且唯一，设置成功后函数返回原 filter，尽量兼容原 filter，尤其 DLL 注入时，可能原 filter 中有些不能丢掉的逻辑。而相对来说 VEH 是一个链表，可以挂很多。

> ❓ TRY/CATCH
> 我们程序中写的 try/catch，在编译时就全部提取出来了，放在 PE 中。
> PE 结构中的数据表段，Exception Table，存放的是 RUNTIME_FUNCTION，用来确认发生异常的地方是否有对应的处理代码，一个函数不管几个 try/catch 都只生成一个 RUNTIME_FUNCTION，它的结构是 BeginAddress/EndAddress/UnwindData。
> UnwindData 指向的内容定义了 ExceptionData 和 错误处理执行函数
- > ExceptionData 结构名叫 SCOPE_TABLE
   - > 函数中所有 try/catch 块组成的数组。里面定义了 try 开始的地址，catch 的地址，继续往下执行的地址等
- > 错误处理执行函数
   - > 定义怎么查找 SCOPE_TABLE，以及找到后怎么构造能用的堆栈
> 常使用的异常处理语句，有 try/catch 和 __try/__except/__finally，带下划线的是 windows 才有，非 c++ 标准。它们之间的不同在于，__try 是 windows 底层的实现，主要用于 C 代码，不涉及对象管理。try 可以认为是 __try 的扩展，用于 c++ 代码。
> UnwindData 的所有目的，只为了在发生异常时，能够恢复出一个可以继续往下执行的堆栈。编译器给 __try 生成的 SCOPE_TABLE 只有基础信息，比如要恢复多少栈空间之类。而给 c++ try 设置的 SCOPE_TABLE 中带有 RTTI 用以描述对象内存结构，包括虚表、继承关系之类，所以它可以在异常堆栈重建时，对已生成的对象做正确的析构。
> 函数中有对象时，__try 是编不过的，因为发生异常后，堆栈无法被正确恢复。
> try 默认搭配 throw 使用，没有throw 的可能被编译器优化。c++ 代码中可以使用 try/catch 组合，并设置编译选项 /EHa，防止被优化。
> 使用 __try 时，默认的错误处理执行函数是 _C_specific_handler，对应 c++ 中使用 try 时，默认的错误处理执行函数是 __CxxFrameHandler。它们做的事情是差不多的，搜索 SCOPE_TABLE，从异常中恢复、构造新堆栈。

在做桌面软件时，一般都需要分析崩溃率，以确认产品稳定性。这里经常用到的就是 VEH/SEH，在错误发生时，自身的程序记录下错误现场，使用 `MinidumpWriteDump` 这类函数生成 dump 文件，上报到监控中心，最后 exit 体面退出，其后再由守护进程拉起来，不让 csrss.exe 弹框 ”xxx 程序已停止运行“ 来影响用户观感。

崩溃，以桌面软件来说。

- 一般新上线的功能，比如刚开始灰度，崩溃率大约百分之一，这是受限于内部环境，测不出来的问题。
- 常规功能大约千分之三，这是修复了不少反馈的问题之后的结果。
- 运行了很长时间，且一直在跟进修复的模块一般大约万分之五。

正常情况，严格遵守良好的设计和编码以及完备的测试，再持续跟进修复，其崩溃率应该在千分之三内。而大公司追求的低于万分之三，除了要有很好的架构设计和规范编码，还要很强的查错机制。从千分之三到万分之三，中间有很大的技术Gap，需要一个很强的底层团队。另一个桌面软件受第三方影响较大，部分不稳定性是引用的第三方模块或者本机安装的第三方程序引起，如果是移动端 App 则在这块要好一点。

### CRT

Crt 通常是指 C/C++ 运行时库，有很多实现版本，最主要的功能是封装了 c/c++ 库函数。

正常情况库实现是链接到 msvcrt，或者它的升级版 ucrtbase，而 Visual Studio 编译的程序，可能还会链到 vcruntime，它里面提供了一些 Visual studio 专有函数，或替换了 msvcrt/ucrt 中的某些实现。

Crt 的初始化，这里以 msvcrt 的升级版 ucrtbase 举例。

```other
- MD编译加载 ucrtbase.dll，在 DLL 入口点初始化
_acrt_DllMain 
  _acrt_initialize 
    _acrt_execute_initializers(&crt_initializer, &initialized);

- MT编译内嵌crt 代码，在 EXE 入口点初始化，内容是一样的
_scrt_common_main_seh
  _scrt_initialize_crt
    _acrt_initialize 
      _acrt_execute_initializers(&crt_initializer, &initialized);
```

最初 crt 是单线程的，所以有很多全局变量。后续扩展了多线程支持，于是将这些全局变量使用了一个 `_tiddata/_acrt_current_locale_data` 装起来，放在 Tls 槽里面占一个 `ETHREAD.TlsSlots`。其中有一个 `pthreadlocinfo` 结构，里面有一个指向 `_XcptActTab/_acrt_exception_action_table`的指针。指针主要为了 `abort/assert` 这些 c++ 定义的库函数，还有控制台程序的 `signal`。现在改 ucrt 之后这些变量、函数什么的都 _acrt 开头。

crt 两个经典的出错，堆损坏和跨模块操作内存。

堆损坏：

1. 以 Windows 底层 `HeapAlloc/Free` 实现malloc/free 举例。crt 中使用 malloc 分配内存时，并不只分配指定大小，还有一个 header，用来描述内存块状态。空闲内存块是挂在FreeList 上的，分配时就 pop 出来，以此可以加快内存的分配速度。
2. 当调用 free 时，先通过指针找它的 header 看它的状态，检查对齐、Busy 位之类几个地方，如果没问题，就认为是一个正确的header，重置，挂回FreeList。
   1. 这里有一个风险，就是十分巧合的情况下，给的不正确的内存指针，但是检查通过了。此时如果原来的内存被修改，覆盖了假设的header，就会把 Heap 的 FreeList 写坏。造成堆损坏。

跨模块操作内存：

1. 分配与释放属于不同堆
   1. 全MT/全MD，堆角度，堆会保持一致。MT使用进程默认堆，MD 使用ucrt/msvcrt 模块
   2. 全MT
      1. Windows 早期的MT 没有统一使用进程默认堆，崩的很快，后来改进了
      2. 全MT 还有有个全局变量的风险，一些结构为了优化性能，将空值定义为了全局变量，在析构时判断数据指针的地址是否与空值地址相等，跨模块析构时每个模块空值地址不同，此时大概率要删错内存了
         1. 类似的还有单例模式，MT 下单例是模块范围不是进程范围。这里也容易出问题
   3. MT+D
      1. 这种模式到处是问题，很偶现的产生堆损坏，偶现产生访问异常崩溃，必然产生内存泄漏
         1. 没有源码集成第三方模块容易出现这里的问题
2. 模块编译时 crt 版本不一致
   1. 版本不一致可能导致函数实现不一致，使用的参数可能结构体实现都变了。此时操作跨模块的内存大概率崩溃
   2. 除开 crt 版本比如 c++98/c++11，编译器版本也需要保持一致比如 msvc120/msvc140
3. 优化选项不一致
   1. 不同的编译选项，分配的内存或结构体，它的大小和实现可能不一致。比如release 下分配的内存就要比 debug 下少一个 block header，此时 release 的内存传递给 debug code，只要操作 block header 内存就要出错
4. 内存对齐不一致导致内存布局不一致
   1. 一个模块使用 push pack(1)，另一个使用 push pack(4)。跨模块操作时，模块之间结构体内的数据偏移出错，很容易出现数据损坏，最容易表现为析构时崩溃

为了尽量避免上边的问题，在DLL 导出接口时，通常要求参数和返回值都是初始数据类型，不涉及对象构造。以此避免自动构造对象过程中，内存分配不明确，或因为各种原因导致的对象结构不一致。而对于内存释放，应该秉持谁分配谁释放的原则，这样即使模块之间实现不一致，也不会损坏内存以及内存管理Heap。

CRT 中，Debug 模式的内存分配在原来的 header 基础上再加了一个 header 用来做统计和检查，链在一个 block list 上，每个block header 存放了文件名、行号之类更详细的数据。分配和释放时，也检查的更多。包括释放时检查这个指针是不是落在正确的 block list 中。碰到意外情况，会弹 `assert` 的框。通过 block list 实现`_CrtDumpMemoryLeaks` 这类辅助函数，检查内存泄漏。

Release 和 Debug 内存检查上面的区别可以对比 msvcrt/ucrtbase 与 ucrtbased.dll 的函数实现。开发与功能测试时应该使用 `Debug` 模式运行，以尽可能的暴露问题。即便`Release` 测试，也可以通过 `appverif` 和 `gflags` 开启一些内置的调试与检查标志。

在使用 STL 时，同样参考 crt 的问题，STL 可能会隐藏的更深。因为它的内存操作封装在对象中，需要思考对象构造与析构带来的内存变化。举几个例子。

- 等于号赋值

   等于号实际调用对象的 operator= 操作，类实现中可重载这一函数。系统默认的行为是对类中的成员逐个调用 operator=，如果类中定义指针，这个成员重载是直接赋值。这里常见出错场景是等于号赋值后，原结构体析构，新结构体中的指针默认还指向原内存块，此时使用产生未知访问。

   c++11 加了右值拷贝与std::move。其一是避免大的结构体逐一赋值的开销，其二也可以cover 忘了操作指针拷贝的风险。这个版本在编译时给每个用户定义的变量增加了中间指针，变量不直接索引内存，而是索引指向内存的指针，包括全局变量也是这样设计。这样拷贝时，改变目标变量指向的指针为源变量即可，之后源变量重新初始化。swap 的道理是一样的。

- 返回局部变量对象

   调用一个函数，栈操作通常是先参数、然后返回地址、rsp、局部变量，当然现在x64 大都使用寄存器传参，调用完成由 rax 将结果带回。

   以前c++ 代码禁止返回对象，比如 std::string，可以说因为编译器 RVO 返回值优化不完善，也可以说这样会破坏变量的作用域管理。函数返回前会调用局部变量析构，这是正常的，此时如果返回对象，rax 会返回局部对象的地址，但此时调用者拿到地址指向的内存其实在返回前已经析构了。所以之前取对象比如 std::string 一般是外部定义，然后传地址到函数里面操作。

   现在可以直接返回，是编译器把传地址这一步自动完成了，子函数里面直接操作外部对象。

- 临时变量的隐性释放时机

   代码中有时候采用函数的形式返回类实例，比如 `GetInstance().doSomething()`。如果获取 Instance 返回临时变量，那么调用完 doSomething，实例会被析构。如果从 doSomething 拿了什么对象内的数据，很容易异常，一般这样取实例的要求返回全局变量。

   vector/map 的迭代器是一样的道理，迭代器可以看作一个指向真实数据的指针，在操作数据时，erase、insert 之类都会改变原容器的内存布局，此时拿着的迭代器指向内容变得不明确

在大多数的崩溃场景中，除开没有严格遵守规范的开发，引起 crt 崩溃的往往并不因为 crt 或 stl 本身，而多是数据的生命周期控制问题。换句话讲，上面提到的这些问题，只要定义、执行好编码规范，都是容易避免发生的。而不容易避免的，往往是逻辑上的问题。尤其是现代的应用，必然引入多线程、异步、锁以提高性能。再加上接口指针导出到不同模块使用，接口拥有者释放或变更时没有通知到位。这其实是程序设计问题。

只从崩溃的角度上来说，COM 使用引用计数维护对象生命周期，c++ 11 使用同样的思想引入了智能指针，通过最后一个使用数据的人来发出释放动作，有效的改善了崩溃。java、c#、go 则引入gc，屏蔽直接指针使用，在内存使用、删除上增加检查，改善崩溃。rust 通过锁死内存的拥有者，让内存的生命周期与拥有者作用域绑在一起，反向限制代码，解决无效指针和它衍生的问题

但这些改进是辅助，回到最初，不管使用什么语言或技术，还是要规划好，什么内存在什么逻辑层次中使用

### Main函数

兜兜转转，程序终于执行到 Main。事实上中间很多步骤略过了，比如文件系统、网络栈、锁、HOOK、注册表、鼠标键盘、设备驱动、SAM、Hyper-V、AppContainer 等等。还有 explorer 这个复杂的 shell 程序，而且除了系统上的模块，在实际的公司使用电脑中，通常还会有多个第三方厂商的软件进行参与

在电脑上双击进程图标，瞬间进程弹出来，看似短暂的时间，实际整个操作系统几乎都参与了这个过程。操作系统是效率和稳定性兼得的典型例子，有许多值得借鉴的设计，我们写的代码最终要跑在操作系统上，符合它的设计，可以避免预期之外的事情发生

