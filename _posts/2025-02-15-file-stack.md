# Windows文件系统设备栈

## 开头

文件系统在实际的应用中有广泛的需求，比如杀软，需要扫描文件内容中是否有恶意代码，EDR需要获取进程的文件行为，比如加密软件，需要加密文件内容，或是文件磁盘、沙箱隔离需要改变文件访问与读写逻辑  
Windows NT 是对象管理系统，系统资源都以对象的形式存在。在内核中，访问对象的接口分3 层，最上层是具体的功能对象，比如File、Hive、Process 等，中间是设备对象 DeviceObject，底层则是硬件对象Pnp Device Node  
当然并非所有对象都从设备来，只有io 对象才是，ntoskrnl 提供了大多数内存形式的对象  
创建文件的过程，以此流程，先经过 ntoskrnl!iomgr 以IRP 访问设备对象，设备对象再读写具体硬件。其中 iomgr 在这里的接口是`IopParseDevice/File`，设备对象的接口是 Device 路径，硬件对象的接口是 InstancePath

文件的设备栈按逻辑可以分为 文件系统设备栈、卷设备栈以及存储设备栈

## 设备栈

Windows 内核中将硬件抽象成`PDO- Physical Device Object`，提供最基础的读写框架。要具体使用硬件实现功能，需要各个功能驱动创建FDO 附加其上，这是基础的设备栈概念。驱动在这个过程中扮演代码载体的作用，通过创建设备对象附加到对应的设备栈中，以处理经过这个设备栈的请求  
内核底下的驱动调用比较直接，`IoCallDriver` 直接调用驱动提供的分发函数。在这个调用中，有几个对象的关系先明确一下，其实都是设备对象，区分一下叫法

- Driver Object 驱动对象  
驱动加载后由ntoskrnl 创建，`IopLoadDriver/IoCreateDriver`。驱动对象最大的作用是绑定了Dispatch Table。处理IRP 时，调用`DeviceObject->DriverObject`的派遣函数
- Control Device 控制设备 CDO  
一般是为了提供SymbolicLink 创建的，提供给R3 打开并`DeviceIoControl`发送控制命令。这个不一定有，因为发命令还有许多其他途径
- Physical Device 物理设备 PDO  
从功能划分来说，PDO 里面一般存放各类硬件信息，以及跟硬件通信的逻辑，还有该类硬件跟操作系统交互必须实现的接口。从创建者来说，PDO 一般由`PnpManager/Bus`驱动创建。从设备栈的结构来说，这个设备处于栈最底层
- Function Device 功能设备 FDO  
从栈上的位置看`AttachDevice`到PDO 上层的都是FDO，这里有可能还分出一个Attach 到FDO 的FiDO 过滤设备。PDO/FDO/FiDO 更多是一种相对概念，跟处于栈中的位置强相关

### 驱动模型

从物理连接关系看，硬件设备大多通过`PCI/PCIe` 或`Usb、SATA`线之类的连接。主板上提供的硬件插槽有多种形式，最基础的是PCIe 规范，Cpu 中集成了PCIe 控制器，为高速数据交换提供支持。硬件接入PCIe 插槽后，插槽与PCIe 控制器以PCIe 的协议进行点对点通信。在Windows 内核中有总线驱动`pci.sys`，其中定义了最基本的硬件交互逻辑，比如硬件寄存器读写、中断调用管理

在PCIe 的基础上，为了更好的支持不同接口不同种类的设备，主板将一部分内置的PCIe 插槽做成了桥接控制器，包括SCSI 控制器、IDE 控制器、USB 控制器等，对外提供不同种类的插槽，接入控制器的设备以它们自定义协议内部通信，到达控制器后回到PCIe。主板上PCIe 的槽是有限的，一般显卡、NVMe 高速存储、高性能网卡这类大量、即时的设备优先接入PCIe 的卡槽，其他设备比如硬盘、cdrom、usb、音频之类则接入桥接控制器，多设备共享一条Line

与硬件通信线路相似，逻辑上，Windows 定义了逻辑总线Pnp，构建过程实现在`ntoskrnl!IopInitializePlugPlayServices`，创建`\Device\PnpManager`的Driver Object，构建逻辑上的整机硬件设备树。设备树是一颗树的结构形式，节点与硬件一一对应，关键字是硬件接入到主板的总线地址/Bus地址，`总线ID+设备槽ID+功能ID`，Cpu 中的PCIe 控制器使用这个地址定位硬件

Windows 启动过程中Phase1 开始时，要初始化IO `IoInitSystem`，其开头就需要初始化逻辑总线Pnp。初始化时先构建顶层节点`IopRootDeviceNode`，这是一个虚拟的Root Bus，注册表配置路径`ControlSet?\Enum\HTREE\ROOT\0`。每个Device Node 都有2 个必要的设置  
- 其一是注册表`Controlset?\Enum` 下的`InstancePath`，Pnp用这个路径定位树中的设备  
- 其二是总线地址，Cpu 用总线地址定位物理硬件  

`IopRootDeviceNode`构造了一个假的Bus 地址，其后与`InstancePath`一起，创建一个PDO。Root Node 构造完成后，使用`PiProcessReenumeration`开始枚举子设备。Pnp 设备树中的每一个设备 DevNode，都代表一个物理设备(可以是虚拟的)，每个物理设备都有设备栈

枚举子设备通常是经过  
- FoundDevice  
Bus 驱动经过一些自我检索的动作后`IoReportDetectedDevice` 将挂在自身的新硬件报告给Pnp。Pnp 获取硬件总线地址，在注册表创建InstancePath、配置硬件状态、创建PDO，创建关联的Device Node，保存到设备树
- AddDevice  
Pnp 根据取到的硬件ID 查找能让硬件开始工作的驱动，找到后加载到系统，调用指定驱动的 DO->AddDevice 为这个硬件节点创建设备栈
- StartDevice  
设备栈创建完`IoGetAttachedDevice`取栈顶发送`IRP_MN_START_DEVICE`，初始化设备需要的资源开始干活
- EnumDevice  
Bus 设备Start 后要继续枚举子设备，往设备栈发送`IRP_MN_QUERY_DEVICE_RELATIONS`，枚举过程发现子设备后又进入FoundDevice

首次枚举，`IopRootDeviceNode`被当作已经Start 的设备走枚举，实际它底下没东西，这里特殊处理了，用`IopGetRootDevices`去`ControlSet?\Enum\Root`读预定义的Bus 硬件。Bus 读出来后，回到枚举流程，走同样的流程，不过此时有真实数据  
在Bus 的枚举例程中，找到设备后`IoReportDetectedDevice`将设备的基本信息报告给Pnp。Pnp 收到消息后取数据做好配置然后`PipAllocateDeviceNode`为新发现的硬件创建DevNode，再通过`PipCallDriverAddDevice`启用这个Node，启用时，根据硬件设备ID、兼容ID 去注册表查找这个ID 对应的InstancePath 配置  

硬件ID 的可能形式  
```other
0x1234 0x5678 0x9ABC 0x01
PCI\VEN_8086&DEV_1C3A&SUBSYS_1C3A8086&REV_00
```

Pnp 会将识别过的设备写配置到注册表InstancePath，没识别找不到配置的，需要经过一次检索

- 此时尝试查找系统中已加载的驱动配置项。在`ControlSet?\Control\Class`中，Windows 对每种Bus 上的设备都内置了一些驱动配置。Class 子项中有INF 文件名字和`MatchingDeviceId`，新发现的硬件ID 如果能够与某个Class 匹配上，就可以直接用对应的INF 文件加载驱动，并且更新到硬件的InstancePath 配置

匹配不上的就先放着，不是内置支持的硬件，Windows 启动后可以在设备管理器查看带问号的设备，可以为它们手动安装驱动

识别过的硬件在Bus 的InstancePath 目录生成对应硬件ID 的配置项，例如`ControlSet?\Enum\SCSI\xxxx`，其中

- Driver 值存放硬件驱动INF，指向`ControlSet?\Control\Class` 中某项的子项
- Service 存放类驱动的服务名，指向`ControlSet?\Service`
- ClassGUID 值关联到类驱动的安装和配置`ControlSet?\Control\Class`，描述该如何安装、启动对应的类驱动 [https://learn.microsoft.com/en-us/windows-hardware/drivers/install/overview-of-device-setup-classes](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/overview-of-device-setup-classes)

硬件驱动这里出现内部的一些概念，比如类驱动

- 硬件驱动最终的目的是要让设备实现功能，但许多设备的功能是相同的，可能只有接入方式不同，这里就拆分出功能驱动和端口驱动。功能驱动在上层实现逻辑上的功能，端口驱动在下层实现对硬件的读写，这样对于相同功能不同接入方式的硬件，只需要使用不同的端口驱动即可，比如disk.sys 和 scsiport/storport/ataport
- 上边分离出的，功能部分，就称为Class Driver 类驱动，比如 cdrom/disk/kbdclass/monitor 等，类驱动一般由微软实现。同时类驱动之间与Pnp 交互的部分被抽离出 classpnp.sys，在其内部实现了与Pnp 的基础交互并提供了Callback 让用户代码填充，使用`ClassInitialize` 可以填这些回调函数。这样class 驱动的编写可以更专注于功能实现。classpnp 类比DLL，不占用设备栈
- 分离了功能和端口，在端口上还划分了一层。比如硬件厂商推出的多种硬件其端口驱动大部分相同，小部分不同。以此微软将端口驱动再拆分出一个小端口驱动。普通端口驱动遵循接入控制器的接口标准由微软来实现，小端口驱动则加载到同一个设备栈更低位置，以此可以自定义一些特殊的功能或协议。比如 scsi miniport，aic78xx.sys/ql2300.sys。普通硬件的使用，大多数使用端口驱动就足够，有个例外情况是网络栈。网络栈自定义的情况很多，ndis.sys 可以看作是一个端口驱动，其下几乎每个厂商都自己提供的小端口 rtl8187.sys/b57nd60x.sys/e1000.sys

所以一个比较典型的硬件驱动设备栈由`class/port/miniport`组成。硬件要正常工作，需要同时启用端口驱动和Class 驱动。加载`Driver`配置中的INF 后，为了保持设备栈完整，还需要将`ClassGUID`中定义的类驱动上层`UpperFilters`与下层`LowerFilters` 都加载到系统

这些驱动都加载进系统后，Pnp 做一个临时列表，`ReferenceDriverObject`取列表驱动对象，包括 port/class/upper/lower，以PDO 往驱动列表从下往上发送`AddDevice`，让这些驱动创建自己的FDO 附加到PDO 形成最初的设备栈，之后再取TopDevice，发送`IRP_MN_START_DEVICE`，此时设备就算启动了。对于非总线设备来说，此时枚举完成，总线设备将继续嵌套枚举

> 硬件识别  
> 非内置硬件ID 的硬件，初次识别与驱动安装走`SetupDi*` 与`CM_*` 的逻辑。Windows 系统目录下有DriverStore 目录，存储所有安装到计算机的硬件驱动，对应注册表SYSTEM\DriverDatabase。在DriverStore 中，有c_xxxx.inf 和实际的 xxxx.inf 用来描述某个驱动支持某些硬件ID 的设备。如果本地匹配不到，还会发给 Windows Update 从微软的数据库里面找。安装过程先是以Pnp 从硬件到达通知中获取的硬件ID 去匹配inf 中支持设备字段，匹配成功后将对应驱动复制到`System32/drivers`并设置注册表中该硬件的配置项，下次Pnp 初始化时即可构造设备栈

```other
- 列出本机的硬件设备
powershell> Get-PnpDevice | Select-Object -Property DeviceID, Class, 
FriendlyName, Manufacturer, Status, InstanceId, HardwareID
```

实际在Bus 的枚举过程中，Windows 还配置了一些虚拟的Bus。比如`hvservice/kdnic/volmgr`等，这些Bus 对应的驱动设置了`DRVO_BUILTIN_DRIVER`标记，在Pnp 发现设备的流程中，对于这类驱动报告的设备，不用关联到总线地址

> 监听设备变化
> 对于设备在Pnp 设备树上的变化，Pnp 做了一套通知机制，定义了几个链表，驱动程序使用 **IoRegisterPlugPlayNotification** 注册回调函数等待Pnp 通知
> - *PnpProfileNotifyList* 主要是整机范围硬件移除，或者设备增加、更新驱动INF 配置
> - *DeviceNode*中的*TargetDeviceNotify*，这个就纯是某个硬件的移除通知
> - 还有*PnpDeviceClassNotify*，Windows 为系统上的所有设备，以功能划分创建了类别，叫做接口类，接口类是纯软件逻辑的概念，本身底下可以放同类功能物理设备的InstancePath。这样的好处是，访问硬件资源只需通过接口类ID 即可，不需要知道每个设备InstancePath
> 接口类所有类别写在注册表**ControlSet?\Control\DeviceClasses**下，内核程序可以使用**IoRegisterDeviceInterface**将自己注册到某个接口类，其他内核程序可以使用开头的函数注册监听这个类底下的设备变化，主要是 Arrival 和 Removal
> 过程像这样
> - 内核程序使用 IoReg + 接口类Uuid 监听某一类设备的增加/移除
> - 某类功能的硬件注册到接口类
> - 内核程序将得到硬件注册通知

在`IoInitSystem`的开头位置，使用`IoInitSystemPreDrivers`初始化重要内核结构、加载一些早期的驱动程序，包括Pnp 的初始化也在这里调用。设备树构造过程中，有些驱动逻辑中可能依赖还未构造的设备，导致逻辑失败。对于加载失败的，内核会将它们挂在一个列表中记录下来。这些驱动中往往填充了ReInit 的函数。设备树构造完成后，内核调用`IopInitializeBootDrivers`加载系统中定义为Boot Start 的驱动，再读入之前加载失败的到列表，调用`IopCallBootDriverReinitializationRoutines`，让所有已加载的驱动在设备树完整时执行一次Post 操作

### 卷设备的初始化

在磁盘设备枚举构造过程中，存储栈初始由 partmgr/disk/xxxxport 创建

- 在AddDevice 阶段disk.sys 创建`DRx`的FDO
- 在Init 和Start 阶段disk.sys 创建`DiskX\Partition0`指向`DRx`
- partmgr 的Start阶段先等底层执行完成，然后使用`Partition0`完成自己的初始化工作
   - 首先查询磁盘物理位置信息并注册类接口`GUID_DEVINTERFACE_DISK`，iomgr 和pnp 等模块会使用这个类接口枚举磁盘
   - 然后`PmReadPartitionTable`读分区表，取到分区的layout，再`PmUpdateLayoutEx`创建分区对象，这些分区对象不是Device
   - 分区对象以内部数据列表的形式存在，操作磁盘与分区依然采用 Partition0

volmgr 在Pnp 枚举过程中作为一个**虚拟Bus** 设备被加载

- 在volmgr 驱动的DriverEntry 中，`IoReportDetectedDevice`将自己注册为一个虚拟硬件设备，报告给Pnp 取到PDO 后，用`IoRegisterDeviceInterface`将自己注册到类接口`VOLMGR_VOLUME_MANAGER_GUID`
- 在partmgr 驱动的DriverEntry 中，`IoRegisterPlugPlayNotification`对这个类接口注册了变动通知，当VOLMGR 接口增加设备时，partmgr 发生回调
- partmgr回调`PmVolumeManagerNotification`，这里将物理磁盘分区发往volmgr

在卷管理设备到达的事件中，partmgr 将内部分区对象以`IOCTL_INTERNAL_VOLMGR_PARTITION_ARRIVED`发送给volmgr，volmgr 收到后读分区位置偏移、磁盘扇区等信息，分配分区ID。为分区对象创建逻辑卷设备`\Device\HarddiskVolumeX`，类型`FILE_DEVICE_DISK`，并和磁盘PDO 一起保存在内部`VolumeList` 中。后续动态插拔的磁盘设备，则是在partmgr 的枚举子设备BusRelations 中将新的分区报告给volmgr，partmgr 本身不向Pnp 返回物理设备

这里做了一层隔离，volmgr 本身作为一个虚拟的硬件节点在设备树上，本身volmgr 创建的FDO 也不附加磁盘PDO，调用时通过FDO 的`DeviceExtension`索引Partition0，成为一个独立的设备栈

## 文件系统层

在Windows 的对象管理器中，`\FileSystem` 目录下列出当前计算机加载的所有文件系统驱动，大的方向上可以分为本地磁盘文件系统和网络文件系统

在这里，就先以本地磁盘文件系统的实现，来接着上边的卷管理器继续探讨

文件系统的设备栈是纯逻辑的概念，不基于虚拟或真实的硬件，由ntoskrnl!iomgr 管理。文件系统是iomgr 操作文件设备的唯一入口，即使一块磁盘没有被格式化，iomgr 依然通过`RawDisk/CdRom` 这样的内置文件系统访问磁盘。实现文件系统的驱动可以使用`IoRegisterFileSystem`注册文件系统对象，存放在`ntoskrnl!iomgr_xxxFileSystemQueue`中，比如IopDiskFileSystemQueueHead

文件系统与卷设备是两个独立的设备栈，就像volmgr 与disk。volmgr通过FDO 中DeviceExtension 保存的Partition0 访问磁盘。文件系统则是由 iomgr 直接填充 volmgr FDO 的Vpb 成员来作为访问入口

- 访问文件时，用户代码传入 Nt/CreateFile 的文件路径，描述的是卷设备路径  
- iomgr 取卷设备的Vpb，将IRP 发送给`Vpb->DeviceObject`，这是文件系统生成的设备  
- 而文件系统设备往下层调用时，则取`Vpb->RealDevice`，这是卷设备的FDO。本地磁盘文件系统的卷设备要经过`IRP_MN_MOUNT_VOLUME`才能被iomgr 使用  

为了区分文件系统创建的卷设备和volmgr 的卷设备，这里用**物理卷**代表volmgr 的设备(虽然实际是逻辑卷)，而用**文件系统卷**代表文件系统的设备

这里以解析一个文件创建请求为例看它的调用过程。NtCreateFile 进入`ObOpenObjectByName`，首先是循环解析路径，去系统对象表中找对象，以`\Device\HarddiskVolume0\A.txt`为例

- 取第一个`\`，这是Object Table 的Root，不用做什么  
- 取到Device，打开Device 对象目录  
- 取到HarddiskVolume0，调用Device 对象的`ObjectParseProcedure`→`IopParseDevice`  
   - 如果碰到`\??\C:\`这样的符号名，则读出符号指向的实际路径再继续  
   - Parse 过程中，检查HarddiskVolume0 是否关联到VPB`IopCheckVpbMounted`  

文件系统的设备需要关联VPB 以支持底层操作

- 在检查到`HarddiskVolume0->Vpb->Flags & VPB_MOUNTED`为0 时，意味着用这个名字查不到文件系统卷，此时调用`IopMountVolume`尝试将它挂载到文件系统  
- `IopMountVolume`会根据物理卷的磁盘类型定位`xxxFileSystemQueue`中对应的文件系统设备列表，并向列表中的文件系统设备发送`IRP_MN_MOUNT_VOLUME`  
- Queue 列表初始状态只有一个`fs_rec`  

Windows 启动过程 `IoInitSystem` 时调用`IopInitializeBootDrivers`，在这里加载系统中Boot Start 类型的驱动，其中就有个`fs_rec.sys`，在这个驱动的DriverEntry，`IoRegisterFileSystem`注册虚拟的文件系统，它只实现一个`IRP_MN_MOUNT_VOLUME`。但并非真的mount，而是读物理卷的前几个扇区，用以识别这个物理卷的文件系统。取到内容后返回`STATUS_FS_DRIVER_REQUIRED`告知iomgr 需要加载什么文件系统驱动

- iomgr 加载新驱动，新驱动注册文件系统`IoRegisterFileSystem`  
- iomgr 再发送mount，新驱动响应mount，创建一个FDO，将这个FDO 存为`Vpb->DeviceObject`。这个FDO 不附加物理卷  
- iomgr 顺利拿到Vpb 后，取Top DeviceObject，继续Parse 得到文件系统根目录FileObject  
- 最后取到A.txt，进入`IopParseFile`，构造IRP IRP_MJ_CREATE 发往文件系统卷  

Windows 为文件系统设备变化提供了监控API `IoRegisterFsRegistrationChange`，当文件系统设备增加或移除时获得响应。sfilter/FltMgr 均在文件系统设备变更回调生成监控FDO 并附加，因此当文件系统设备收到 mount/umount 事件时，sfilter/FltMgr 先行得到通知，此时等待文件系统 mount 结束生成文件系统卷后，就可以创建FDO 附加到上面

在上边的解析中，`VPB- Volume Parameter Block`用来关联物理卷与文件系统卷。在Vpb 中定义了 DeviceObject 和 RealDevice

- DeviceObject 指向文件系统卷  
- RealDevice 指向物理卷  

这里有令人疑惑的地方，为什么文件系统卷不附加到物理卷的栈上。这里猜测可能的原因还是功能上的分层设计，文件系统操作的是文件、目录，而volmgr 操作的是整个分区，与此类似的还有disk 操作的整个磁盘与volmgr 也是分离设计的。分离文件和分区，可以更方便的替换某一层的实现。

后续的文件操作都将取文件系统卷设备的栈顶进行，除非使用Object Hint 指定了目标。而文件系统卷的设备栈，就是最广泛的文件过滤驱动待的地方

### 与IO管理器的接口

每个文件系统都有自己不同的设计，但大多是要在FDO 中创建管理结构，而管理结构中再引用物理卷做实际的动作。不同的文件系统，它们的管理结构、存储结构、实际动作等各有不同的实现，但此处有些 iomgr 定义的接口，是所有文件系统都需要遵守的

**FILE_OBJECT**

访问文件系统设备使用IRP，参数上下文使用FileObject

Windows IO 管理器将文件封装成文件对象，一个文件对象由iomgr 填充一部分，文件系统填充另外部分，再设置相应的Flag 来代表其状态。对于文件系统来说，文件对象就是操作系统提供给它的上下文，所有必须的数据，都得关联到文件对象上

**VACB**

文件系统的操作对象最终落到磁盘，但磁盘本身速度很慢，尤其处理小而密的访问。为了提高磁盘的效率，ntoskrnl 中设置了一层缓存，这里的缓存起到的作用与所有缓存一样，削峰填谷。将小而密的操作合成大而疏的操作，将不可预期的偶发性大量操作，变成规律性操作

原理就是读写磁盘前加一层内存，写数据时写到内存即返回，读数据时先读内存中的。另外起几条线程专门批量将内存数据同步到磁盘

> 文件系统缓存与虚拟内存的不同  
> - 虚拟内存主要是打开页面文件的Section 并分成4K 的格子，将系统和进程中的`WorkingSet`挂到Partition 的`WorkingSetExpansionHead`列表中等待Balance 线程将PTE 交换到Paging File 的格子，以腾出物理内存。这一机制为Section 和PagedPool 服务，目的是腾内存  
> - 文件系统使用系统缓存，系统缓存为读写文件内容服务，目的是提高IO 效率  

Windows启动时会占一段物理内存，用做系统缓存，win10 增加Partition 之后从Partition 占用，大概占总数的`1/8`，见`ntoskrnl!CcInitializePartition`。这些内存使用`VACB- Virtual Address Control Block`来管理，系统定义了`CcVacbArrays`数组存放所有Vacb 指针，另外用`CcVacbFreeList/CcNumberOfFreeVacbs`管理指针，Partition 初始化时，`CcInitializePartitionVacbs`初始化系统Vacb 列表

- 每个Vacb 指向一块256KB 的内存，当然初始化的时候没有实际内存，使用的时候再分配。一台8G 的电脑算系统缓存大概1G，有4096 个Vacb，系统Vacb 列表在这里类似限额的作用  

系统Vacb 是一个资源池，代表系统为文件系统缓存预留的物理内存，分配与使用这个资源池，就需要关联到 ntoskrnl iomgr。文件系统缓存的大小可以通过ProcessHacker系统信息里面的CacheWS 查看

这层缓存对于文件系统设备来说，可以选择用，也可以不用。但有和没有缓存之间性能差距很大，常见的文件系统都是深度集成，恨不得把所有东西都塞到缓存里去

**SharedCacheMap**

Windows IO 管理器在 FileObject 中索引Vacb 的使用情况

- `FileObject->SectionObjectPointer`管理文件关联的Section  
   - `ImageSectionObject`以SEC_IMAGE 的方式map 当前的FileObject，是一个ControlArea  
   - `DataSectionObject`以其他方式 map 当前的FileObject，也是一个ControlArea。区分Image 和Data 可能出于逻辑分离的考虑。通常Image 映射成读+执行，用来运行PE、做Section 共享，而Data 通常用于读写文件  
   - `SharedCacheMap->Section`，以SEC_COMMIT 方式map 当前的FileObject，这是个SECTION 结构，内部指向`DataSectionObject`  

一般来说，对Section 操作需要MapView，将Section 的`Segment/ControlArea` 用Vad 描述一下，以此产生虚拟地址给程序使用。在`SharedCacheMap` 中，没有使用Vad，而是跟系统要Vacb，从系统缓存预留的页表项取虚拟地址。为此`SharedCacheMap` 中有个指针数组Vacbs，以256KB 为单位分割当前Section，需要操作哪个地址时，就定位到数组下标，取系统Vacb 填进去，再继续访问

`SharedCacheMap`中记录了当前文件每个打开句柄正在操作的位置，给每个打开句柄分配存储结构`PrivateCacheMap`，所有Private 串在 Shared 的链表里

- 文件进行读写时，如果当下没有关联`PrivateCacheMap`，调用`CcInitializeCacheMap`进行初始化，如果`SharedCacheMap`也没有，同时初始化Shared  
- `SharedCacheMap`初始化时，创建`MEM_COMMIT`的Section，再`CcCreateVacbArray`初始化`Vacbs`成员，就是那个指针数组  

如果文件只是打开，没有读写，那也用不上缓存，也就不需要初始化CacheMap 一堆东西了

**MCB**

文件系统操作的最小单位是簇，使用文件系统设备卷时，先按簇大小分出一个连续数组，索引整个卷的空间，跟内存管理一样，再做个Bitmap 记录占用或空闲

这个表示整个卷空间连续数组的下标叫逻辑簇号`LCN- Logical Cluster Number`。在表示文件数据内容时，Mft 文件记录内部使用文件块的概念，文件块用连续的`0...N`虚拟簇号`VCN- Virtual Cluster Number`来索引，表示文件内容的顺序，文件中的VCN 指向卷的LCN，再设置文件块占几个簇。读文件的时候，就根据VCN 定位LCN 一路拼接起来得到完整文件

因为内容的多次读写修改，文件内容很可能并不是有序存放在卷中的，但对于读写文件的程序来说，它只关心文件内的偏移，不会管你卷的偏移。因此文件系统设备需要有一个结构，将平坦的文件内偏移对应卷的物理偏移，这个结构是`Mcb- Map Control Block`。单个Mcb 代表一块连续的物理存储，如果一个文件存的七零八散，它需要的Mcb 就多点

当要操作一个文件时，首先尝试查找Mcb，如果没找到，再定位VCN，然后确认操作数据区域大小，是不是目标就在一个文件块里面，如果跨文件块，再多生成几个Mcb。Mcb 中主要存储Vbo 和 Lbo，Virtual Block Offset / Logical Block Offset，Vbo 就是根据VCN 来的平坦偏移，Lbo 就是LCN 来的卷物理偏移。Mcb 主要是快速定位平坦偏移到物理偏移，每次都去解析Mft 开销比较大

**BCB**

Vacb 关联到系统缓存的PTE，Mcb 关联到文件存储，把这两个关联到一起的，是缺页机制

文件读写时，先用文件偏移在SharedCacheMap 中定位Vacb 指针，从系统缓存取一个虚拟地址，设置原型Prototype PTE，初始化为Section 的Subsection 地址。memcpy 时，触发缺页，定位到这个Subsection，加上文件偏移，执行`IoPageRead` 把文件内容读出来。这里如果是没读过的内容，会两次经过文件系统设备，一次是普通读取，一次缺页引起的NonCached Paging IO。普通读取是用户发的IRP，无缓存是缺页处理发出，当然如果一开始发的就是无缓存模式，就只有一次

Windows的文件系统缓存与其他系统略有不同。一般来说可能会选择先将文件偏移转成硬盘物理偏移，然后缓存物理偏移对应内容。Windows 先将文件偏移转成Vacb 地址，如果不能命中，再以硬盘物理偏移将数据读出来。减少访问硬盘设备的次数

Windows 将平坦偏移转成Vacb 虚拟地址的过程，使用了一个`BCB- Buffer Control Block`的结构，挂在`SharedCacheMap`上。道理也很简单，不能每次读写都去要一个Vacb，一是资源浪费，二是保证读写同步。Bcb里有`ERESOURCE`锁，还有引用次数，是一个共享结构，对于多句柄操作同一个文件块，它只有一个。它保存平坦偏移 FileOffset，也保存虚拟地址 BaseAddress

iomgr 使用`CcPinFileData`创建Bcb，关联到`SharedCacheMap` 中的pVacb 指针，为这个指针申请系统Vacb，使用`CcUnpinFileData`解Bcb引用，当引用为0 时删除Bcb并释放pVacb 指针。Bcb与pVacb 生命周期比较相似。一个文件块在内存中的状态描述可以是

- 没有Bcb 描述
- 有Bcb，但Bcb 指向的pVacb 没有绑定系统Vacb。因为系统Vacb资源有限，其他进程/线程响应IO 操作时如果取不到就会释放一些已有的
- 有Bcb，指向的pVacb 也绑定了系统Vacb

所以那个PinFileData 的Pin，就是保证绑定了系统Vacb，这样就有虚拟地址，就能走缺页了，而且在函数内部还会调用`CcMapAndRead`主动触发一次缺页。pVacb 只是一个下标索引，Bcb 只是一个内存描述，真正能装文件数据的容器，还得Vacb 的PTE。平常的缺页通常一次只读一页，就是PageFault 那一页，这里为了提高效率，每次读一个Bcb。虚拟内存管理里面有个`PageFaultReadAhead` 概念，可以改变缺页时读入多少数据的逻辑

控制Bcb

- `CcPurgeCacheSection`清除`SharedCacheMap`中所有pVacb，解绑系统Vacb，Bcb 中如果有脏页，写回磁盘。这个函数可以传入标志是否删除`SharedCacheMap`
- `CcFlushCache`清除活跃的pVacb，再把脏页回写

后台的写入线程使用`loAsynchronousPageWrite`回写虚拟内存或系统缓存，在这个函数中发起的IRP 会标记`IRP_PAGING_IO+IRP_NOCACHE`，对于文件系统过滤驱动，需要放过这部分操作

**FSRTL_COMMON_FCB_ HEADER**

为了保持数据一致性，iomgr 定义了一个这样的头，里面有`MainResource`和`PagingIoResource`，分别给两种模式使用，都是`ERESOURCE`锁。Paging 锁只有发生Paging 读写用，其他IRP 会两个一起锁，否则文件内容和缓存一起改，数据要错乱

如果要自己制作一个XXCB，这个锁的逻辑需要加上

**FASTIO**

ntoskrnl iomgr 留了一个接口给文件系统叫 FastIo。文件系统实现时，可以选择响应或拒绝。在一些读/写/判断文件是否存在等场景中，iomgr 不会立即构建IRP 往下发，而是先尝试查找`FileObject->DeviceObject->DriverObject->FastIoDispatch`，找到后先调用，如果没有或者fastio 返回不支持，再构造IRP 往下发

fastio 的调用没有完整设备栈，就是一个直接调用。它提供了一个机会，让某个文件系统设备可以快速的返回比如缓存中的数据，或者本来就可以固定返回的内容。以此提升调用的效率。动态获取的数据或需要经过设备栈取的，不要在FastIo 中实现。fastio 留的接口也都是与缓存操作相关的，ntoskrnl 中FsRtl 实现了一些基础的操作，比如FsRtlCopyRead/FsRtlCopyWrite

FastIo 免去完整的设备栈调用和IRP 开销，可以提升一些性能，但是不实现问题也不大，会少一些性能，为此大多sfilter 的代码中没有使用这套机制，或者使用，但主要在回调中取下层设备，作为一个代理调用下层的处理

文件系统驱动可以使用`FsRtlRegisterFileSystemFilterCallbacks`告知ntoskrnl iomgr 自己实现了FastIo

**OPLOCK**

ntoskrnl iomgr 实现了一个通知锁 Oplock，提供给多人访问逻辑使用，目的是提升IO 效率。锁分 3 种工作模式，level 1 / batch / level 2。level 1 是独占，可以写数据，batch 也是独占，网络共享比如smb 中，可以减少网络请求的频次。level 2 是共享，可以读数据

Oplock 本身的实现就是一个DWORD 标志，通过`IRP_MJ_FILE_SYSTEM_CONTROL+USER_REQUEST+` `FSCTL_REQUEST_OPLOCK`类似的请求改它的这个标志，就一个状态数字。文件系统一般都会响应这个锁请求，先使用像 ERESOURCE 这类真正的锁锁住Fcb/Scb，再调用`FsRtlOplockFsctrl`更新标志，在自身的文件操作逻辑中，调用`FsRtlCheckOplock`先检查标志再做事

Oplock 可能会卡住。对于`IoIsOperationSynchronous` 同步的IRP 请求，在获取Oplock 时会直接返回Status，对于非同步请求获取的过程会Pending IRP，这意味着API 调用会卡住。文件如果被锁住，再操作文件需要等锁释放

类似Smb 这样的Server，Client可以发起Oplock 请求锁住一个文件，lock成功的话，Client可以只操作本地缓存，不用每操作一次就通过网络同步一次数据。等其他Client 去锁同一个文件时，Server 往第一个Client 发送lock break 消息，此时第一个Client 再将缓存一次性发给Server，再回一个Acknowledged，这样就很大程度减少了网络交互

文件系统过滤驱动中还是尽量处理一下Oplock 的IRP

除了 Oplock，文件系统还有个 FileLock，这个锁更多是文件同步或独占目的，不是为了提升IO 效率。FileLock 用户代码用的比较多，这个锁提供了灵活的锁定/解锁能力`NtLockFile/NtUnlockFile`，锁的粒度比较细，可以指定文件偏移/锁定大小/是否独占。锁定后的区域只有当前进程能操作。这个锁在数据处理的软件中用的比较多，Excel/3DMax 类似这种。FileLock 在 FastIo 留了接口用以提高效率

### NTFS

以Ntfs 探讨文件系统的实现

**物理存储结构**

Ntfs 在卷的某个位置写了一个目录，用来放内置的一些管理文件，通过引导扇区中定义的偏移定位。内置目录的第一项是`$Mft- Master File Table`，是当前文件系统卷所有文件的索引表

$Mft 单条记录的格式逻辑上可以分成2 部分，Header 和 Attributes  
- Header  
   - 这是个固定长度的头，内部成员指向第一条属性。每条记录由一个Header 和多个Attributes 组成。操作文件实际操作Attributes
- Attributes  
   - $FILE_NAME 文件名  
   - $OBJECT_ID 索引项ID，提供给OpenFileById 使用  
   - $STANDARD_INFORMATION 属性，创建时间、修改时间、版本  
   - $DATA 数据块文件内容  
      - 文件内容分块存储，里面是VCN/LCN 数组  
   - $INDEX_ROOT & $INDEX_ALLOCATION  
      - 目录文件列表，以文件名为Key 做的B+ 树，用以映射文件名与文件记录Offset。Ntfs目录是有序的  

上边存储结构中Attributes 都可以被单独打开，Admin命令行`>fsutil file layout xxx`可以查看文件的所有属性。对于文件IO 来说，每个文件都可以看作一个目录，操作文件，实质是操作文件的某个属性

**MOUNT**

在处理 MOUNT 事件时`NtfsMountVolume`，首先创建FDO，将FDO 给到VPB。接着读磁盘数据，初始化文件系统卷管理结构`Vcb- Volume Control Block`

初始化Vcb 的时候，先把Mft 解析出来

- 解析Mft 首先要打开 $MFT 文件，Ntfs 内部以`Fcb- File Control Block`代表一条唯一MFT 记录，主要做文件标识的作用  
- 真正读写时，目标是Mft 记录中的属性项，Ntfs 使用`Scb- Stream Control Block`来管理一个打开的属性项，挂在Fcb 下。原始数据以$DATA 属性存储，Scb 本身在系统中对单个文件的单条属性是唯一的，多次打开不会多次创建，以`Scb->AttributeTypeCode`为Key  
   - 常用的Scb 比如IndexScb，指向索引属性，DataScb，指向文件内容  

解析Mft 相当于读取全盘的文件索引，这显然在构造Vcb 的时候不是很有必要。这里先读取 4 个文件，其他的等访问到了再读

- 首先为\$MFT创建Fcb，\$MFT 是内置文件，用SequenceNumber 索引  
   - Fcb 保存在 `Vcb->FcbTable`，是一颗Generic AVL 树  
   - 接着为文件的$DATA 属性创建Scb，挂到Fcb->ScbQueue。一个文件如果属性多那Scb 就多  
   - 当下这个 $DATA 的Scb 保存为 `Vcb->MftScb`  
- 从Vcb->MftScb 读 4 个文件  
   - 读第一个文件，创建Fcb 记录，称为 Root Fcb  
   - 读文件内容，创建DATA Scb，初始化Scb->Mcb，就是那个平坦偏移与物理偏移的数组  
   - 读索引属性，将Root Fcb 的IndexScb 保存为`Vcb->RootIndexScb`  
- 根目录创建后，新打开的文件加进去组成目录树  
   - 给IndexScb 创建`Lcb- Link Control Block`，挂到Fcb->LcbQueue，Lcb 中存放子文件的名字。同时挂到Scb 的子文件索引链表`Scb->ScbType.Index`，这个用来构建目录层级  
      - `RootIndexScb`的 Lcb 保存为`Vcb->RootLcb`  
   - Lcb 是SPLAY_LINK 翻转二叉树，一种LRU 实现。树上最后访问的节点访问速度最快，这种算法非常适合目录浏览  
   - 查找文件时，搜索当前索引Scb 的链表`Scb->ScbType.Index`，里面挂了所有子文件的Lcb，匹配上名字后可以 Lcb->Fcb 定位到文件记录，接着从Fcb->ScbQueue 中取出索引Scb，继续往下匹配，没有索引Scb 的就动态创建  

读完4 条文件记录后，初始化扫描簇占用Bitmap，再读Reparse 表，初始化USN 日志等等，接着设置 Vcb 的状态 `VCB_STATE_MOUNT_COMPLETED`，Mount 结束，回到 iomgr

**创建文件**

创建文件时，是一个路径，其中前边的物理卷设备前缀被iomgr 识别，后续的路径部分发到文件系统卷处理。到达Ntfs 时，依然采用一段一段解析的方式

从传下来的FILE_OBJECT 取出路径参数。当不使用父目录句柄时，则使用 Vcb->RootLcb 开始匹配文件名，否则使用父目录的Lcb。Vcb 中的数据都是已经打开过的文件，找到对应文件名时，则转到Lcb->Fcb->IndexScb->Lcb 继续匹配，如果需要打开的文件已经存在，就不用访问物理磁盘了

碰到没有打开过的文件，比如`\Windows\system32`，现在通过Lcb 找到了Windows，下层没有记录。此时有Lcb->Fcb 取得Windows 目录的Fcb，再打开Fcb 的索引属性，创建IndexScb。以此Scb去磁盘读目录信息并匹配system32，`NtfsLookupEntry`。如果能匹配到名字，从磁盘上的索引内容中取出system32 的Mft 记录偏移，生成Fcb/Lcb节点。后续如果还有更长的路径，定位到新的Lcb，然后重复这个过程

到路径的最后部分解析完时，就需要考虑文件打开是打开哪一个属性。如果是打开索引属性就单独处理，因为查找过程中就打开使用了。如果是其他属性，则另外创建一个`Ccb- Cache Control Block`与Scb 关联起来，加入 Scb->CcbQueue，一个Ccb 表示一个打开动作，对同个文件的同个属性多次打开，创建多个Ccb

Scb 可以看作描述了磁盘静态数据，Ccb 描述了此次打开的参数

- Flags，CCB_FLAG_xxxx 定义`DELETE_ON_CLOSE/IGNORE_CASE/OPEN_BY_FILE_ID` 等等与打开方式相关的标志
- QueryBuffer，目录枚举/监听时的缓冲区
- FullFileName/TypeOfOpen

Ccb 创建完成后，设置FileObject 文件打开的结果

- Ccb 设置为`FileObject->FsContext2`
- Scb 设置为`FileObject->FsContext`
- 如果是打开DATA 属性，Scb中的`SegmentObject`设置为`FileObject->SectionObjectPointer`

这样打开文件的过程就结束了，设置的IoStatus 状态`FILE_OPENED/CREATED` 完成此IRP 回到iomgr。由此可见，对于Ntfs 来说，它只更新FileObject 中 `FsContext/2、SectionObjectPointer、PrivateCacheMap`这几个成员

**读写文件**

Scb 本身也维护一个FileObject 对象，不过更多是使用它的偏移、位置、读写状态之类信息，内部使用，不会传递给上层，在产生读写时创建`(IoCreateStreamFileObjectLite)`

按照io 管理器给文件系统留的接口，读写文件可以先走缓存以提高性能。在NtfsCommonRead/Write 中，先判断当前的FileObject 对应的Scb 是否存在`PrivateCacheMap`，如果没有，则`CcInitializeCacheMap` 生成一个，Ntfs 使用Scb 对接缓存，缓存的操作就是Mcb/Bcb/Vacb 上面的那些，没有什么新设计

不允许缓存的情况，就是直接发IRP 操作了。`IoCreateStreamFileObjectLite` 创建`Scb->FileObject`，关联到Scb->Vcb->Vpb->RealDevice 物理卷的设备栈。之后设置好偏移、大小之类，往物理卷传递IRP。这一层只有扇区、偏移，没有文件、目录的概念

### MUP

Mup 全称是 Multiple UNC Provider Filesystem，是网络文件系统的基础，因为这是ntoskrnl iomgr 访问网络路径的入口。其实从文件系统这一层看，网络文件系统并没有完整的栈，比如WebDav/SMB，它们内部并不维护文件、目录的数据，也不创建卷设备，上层用缓存管理器，下层对接网络栈

假如继续沿用文件系统的说法，其模型与本地的区别很大

1. 所有的网络文件设备驱动，需要先使用`FsRtlRegisterUncProviderEx`将自己的DeviceObject 发给Mup 驱动，再跟一个Device Name。这个名字会被Mup 处理为SymbolicLink，所以访问这个Device Name 就访问到Mup 了
2. 每个设备驱动内部维护一个前缀表格，网络访问请求到达Mup 后它会轮询这些注册的驱动，看有谁认得，如果能识别，直接返回 STATUS_REPARSE 让目标设备处理
3. 设备驱动内部尽量模拟Fcb 之类的结构对接缓存管理器，做事的时候发给网络栈

整体看，Mup 就像一个Router，将进来的请求根据前缀的不同发往不同的设备驱动。而这里的设备驱动像 Redirector，自己不处理，通过网络发给其他机器处理

> mup.sys 启动时创建`FILE_DEVICE_NETWORK_FILE_SYSTEM`的DeviceObject，读取`ControlSet?\Control\Networkprovider\ProviderOrder`下本机使用UNC路径的服务。这些服务会在注册表`ControlSet?\services`设置`NetworkProvider` 和`Parameters` 参数，里面有路径前缀、共享名之类的信息

**MOUNT**

没有卷设备，也没有存储，mount 也不需要了，所有的网络磁盘路径全是 SymbolicLink，解析的过程全走Mup 设备，命中前缀直接REPARSE 到设备驱动，也就不用经过Vpb 取设备对象了

Windows使用rdbss.sys 封装路径的注册和与Mup 的交互，类似classpnp.sys。在rdbss 驱动中导出关键函数`RxRegisterMinirdr/RxStartMinirdr`给Redirector 驱动用，比如

- smb 的实现驱动mrxsmb.sys，调用RxReg 注册`\Device\LanmanRedirector`的路径
- webdav 的实现驱动mrxdav.sys，注册`\Device\WebDavRedirector`路径

同样协议的驱动只需要加载一次，所以同样协议也只需一个设备。Mup 中有一个`MupProviderList` 的全局链表存储路径与`Redirector Device Object`的映射

可能是为了支持`IoRegisterFsRegistrationChange`，网络文件的实现驱动会`IoRegisterFileSystem`注册网络文件系统设备，以此在filter callback 中可以attach 这类设备

**创建文件**

以`CreateFile(\\10.10.0.1\fileshare\1.txt`为例

- 打开前需要补充前缀，变成`\\?\UNC\10.10.0.1\fileshare\1.txt`
- 解析`\\?\UNC`符号连接，打开`\Device\Mup`
- 发送 `IRP_MJ_CREATE` 到Mup 设备打开`\10.10.0.1\fileshare\1.txt`
   - 遍历`MupProviderList`，发送`IOCTL_REDIR_QUERY_PATH`去看看哪个Provider 能识别这个路径前缀

rdbss中维护了一个`PrefixTable`，每一个Prefix 都是一个`Virtual Net Root`虚拟网络节点，通常此时的前缀要么是IP 地址，或是主机名

虚拟网络节点概念

- 每个远程服务地址，都是一个链接，封装成`MRX_V_NET_ROOT`，包含网络地址和用户认证的信息，是网络访问的上下文
   - 还有一个`FcbTable`管理在这个网络地址上打开的所有文件
   - 这些信息关联到Device Object 上
- 每个文件的打开，对应都会创建一个MRX_FCB，设置到`FileObject->FsContext`，每次文件的打开创建MRX_FOBX，记录单个句柄读写Offset 之类的信息，类似Ccb
   - `MRX_FCB`在这里替代了Ntfs 的Fcb+Scb，里面包含
      - `SectionObjectPointers` 接入了缓存机制
      - OpenCount 打开次数
      - RxDeviceObject 回指Provider 的指针

所以它这个找前缀，就是找主机。如果没有找到前缀对应的VNR，则`RxFindOrCreateConnections`尝试连接到远程主机。连接方式由Redirector 自定义，有各自不同的协议，发送数据也有多种方式

- `RxTdiSend` 打开 `\Device\Tcp`，Call Tcp Driver 发出数据，这是最常见的
- `RxSmbdSend`，由`SmbDirect`服务实现，驱动文件 smbddirect.sys。这个Device 依赖于RDMA 硬件，不是所有网卡都有。与DPDK 在功能上相似，这里是直接读写RDMA 缓存不经过网络栈
- `SmbWskSend`

连接如果成功，则创建VNR，保存到Provider 的FCB 中，再填写`PrefixTable`，后续就不用再找，同时更新`MupPrefixTable`，后续就可以不用再发送`IOCTL_REDIR_QUERY_PATH`。此时返回到Mup 的流程继续执行

- Mup重新组装访问路径，`MupiRerouteCreateToProvider`给用户代码路径加上处理它的NT Device 路径。就是给这个访问路由到正确的设备上
   - `\??\UNC\\10.10.0.1\fxx <> \Device\LanmanRedirector\10.10.0.1\fxx`
- 接下来返回`STATUS_REPARSE`
- iomgr 重新打开对应的Device，构造IRP `IRP_MJ_CREATE`打开`\10.10.0.1\fxx`的文件

网络文件系统相比本地文件系统更加的依赖缓存，因为网络收发不稳定且延迟大。Windows 在rdbss 中封装了缓存操作，并把网络文件系统驱动的Callback实现叫 Low IO。当一个读写发生时，比如`RxCommonRead/Write`，其流程与发到本地文件系统没有区别，因为Windows 缓存管理器本身的设计是通用型的。它的区别要到Page Fault 读写这里，对于本地文件系统，取Vpb->RealDevice 发IRP，对于网络文件系统，取VNR 以自己的协议组装网络包发送。Oplock 在网络驱动这里使用比较多，以减少网络请求的发送次数

## 过滤

前边的设备栈，每一层都可以附加自己的设备达成需要的功能，不同的层次包含的能力不一，这里探讨一下如何合理的选择设备栈层次

### 虚拟端口驱动

端口过滤驱动最常见的使用场景是虚拟机应用

在VMware 的虚拟机中，硬件的虚拟化通常都需要搭配端口过滤驱动来实现。虚拟化一个PCIe 控制器，并在其上虚拟化各类物理设备。虚拟化的物理设备如果完全实现操作系统预定义功能，可以直接使用已有端口驱动，如果有定制实现，则需要增加端口或微端口

在云存储的场景中，也可以在本机挂载一个远程磁盘。Windows 的端口驱动中内置了 msiscsi.sys 驱动，对应服务 iScsiPrt。用户代码可以在`ConfigSet?\Enum\Root`中创建一个虚拟Bus，底下创建虚拟磁盘设备，类驱动设置为DISK，Port驱动设置为 iScsiPrt。这个磁盘设备的上层与普通的本地磁盘没有区别，只在port 与硬件的交互中，使用网络通道发送 iSCSI 命令

### 类驱动

Windows BitLocker 全盘加密在这一层。fvevol 注册了`ControlSet?\Control\Class`，可以当作class 驱动加载。驱动在DriverEntry 注册了系统硬件变动通知，在得到硬件变动时判定如果是bitlocker 加密盘，则修改硬件的安装配置，替换原class 使用fvevol 的class 构建设备栈。其他类驱动也大可使用这种方式替换

这一层的加密优势是可以在很初期的时候介入，比如操作系统启动过程中。Windows在EFI 启动程序中支持了BitLocker，这样启用加密的硬盘无法拆下来放到别的机器读取。但对系统来说，比如运行的恶意软件，相当于是不加密的

### 卷管理

partmgr 枚举到分区后，发送通知给卷管理设备，这个发送会给到所有已注册的卷管理设备。此处可以自定义一个

典型的卷管理设备除了有 volmgr，还有volsnap。volsnap是Windows 提供的卷设备快照，启用后，卷设备创建后volsnap 会创建一个FDO 附加其上。不过这一层的FDO 没有文件系统信息，需要自己解析或像volsnap 一样集成一些命令在文件系统的实现里面。这一层一般用作备份还原，像还原软件、影子磁盘之类

### 虚拟物理卷

卷设备通常由 volmgr 创建，但也可以由其他驱动手动创建，此类最普遍的应用就是虚拟磁盘。虚拟磁盘可以创建一个FILE_DEVICE_DISK 的设备当作卷设备，并实现volmgr+partmgr+disk 的接口IRP

- IOCTL_STORAGE_xxx，ClassPnp 存储类型设备需要
- IOCTL_DISK_xxx，本地磁盘类型设备需要
- IOCTL_VOLUME_xxx，卷设备类型需要

最小化实现上述接口，就可以不用接入到volmgr 和 disk 的设备栈，创建一个Device Object 假装是物理卷就行。还可以通知mountmgr 有一个新的卷设备到达，这样可以在explorer 中使用

上层关键的交互IRP 处理后底层的实现比较开放，可以对接内存做成Ramdisk，比如开源的ImDisk。可以对接文件做成Filedisk，比如Veracrypt，Veracrypt 是Filedisk 比较典型的实现，与之类似的还有Windows 自己实现的虚拟磁盘 VHD-vhdmp.sys

一般filedisk 这类会先打开用作存储的那个文件，起几条读写线程。然后让Windows 去格式化它，文件系统会为它创建FDO 保存到Vpb 给 IO 管理器使用，之后就可以给设备创建盘符符号链接，以方便在用户态使用盘符访问。读写线程的逻辑中可以加入加解密的逻辑，这样就能得到一个全盘加密模式的加密磁盘，同时文件内容都落在指定文件里

加密文件磁盘mount 到系统后，就不能很好的保密了。通常加密磁盘会在卷设备的打开/读写处判断来源进程或身份，以阻止未授权的访问，这个判断对一般的ARK 访问有效，比如从自身进程发起的自组装IRP。但不能阻止系统的Paging IO 线程，可以用WorkItem 使用System 的线程去访问。也可以在驱动中 Attach 到符合条件的进程中再访问。另一个，系统中的minifilter/sfilter 一般会附加所有的文件系统卷，这里要使用系统的文件系统来操作这个磁盘，也不太可能绕过它们。除非卷设备的读写中自己实现一套文件系统的逻辑

### 文件系统卷过滤

文件系统过滤的典型应用是 minifilter/sfilter。驱动程序使用`IoRegisterFsRegistrationChange`注册文件系统设备变动通知，在收到mount/umount 事件时，等文件系统设备生成了文件系统卷后附加到卷上，以监控对文件系统卷的操作。有必要的话`FsRtlRegisterFileSystemFilterCallbacks` 实现并注册fastio 接口

在minifilter 的InstanceSetup 回调中，有时会出现 DRx 的设备，这是RawDisk 或Fs_Rec 在mount 卷，可以忽略

minifilter 是一个官方的sfilter 实现，封装了许多细节，在处理minifilter 的事件时，有许多专属于fltmgr 自己封装的数据结构，需要与io 管理器定义的结构对应起来

- FltRegisterFilter → 相当于Driver Object  
这个API 将一个 `FLT_REGISTRATION` 结构挂到fltmgr 的全局变量中，根据注册信息中的Altitude 字段进行排序，数字越大位置越接近栈顶  
- `InstanceSetupCallback` → 关联到 VCB  
对应文件系统已处理`IRP_MN_MOUNT_VOLUME` 事件，此时fltmgr 创建了自己的FDO，这个时机可以让用户驱动分配一个`FLT_INSTANCE_CONTEXT` 关联到fltmgr 的FDO上  
`InstanceTearDownxxx` 就是UMOUNT 事件  
- Normalize/GenerateFileNameCallback  
多数情况下用不到，这两个callback 给fltmgr 的名字缓存使用，fltmgr 会从FileObject 获取名字，FltGet/ParsexxxxName里面也会调用。一般来说，FileObject 与原生的名字对应，但当驱动程序需要对文件做重定向时，这里需要返回真实的路径  
- FLT_STREAMHANDLE_CONTEXT → 类似`ntfs!CCB`  
关联到每个打开句柄  
- FLT_STREAM_CONTEXT → 类似`ntfs!SCB`  
关联到每个Stream  
- FLT_FILE_CONTEXT → 类似`ntfs!FCB`  
关联到文件记录  
- FLT_CALLBACK_DATA → 封装IRP  

fltmgr并不为minifilter 的实例创建FDO 附加文件系统卷，因此所有的minifilter 驱动都在同个设备中根据Altitude 被依次调用，这样的话，Altitude 设置的高的驱动，可以在处理函数中返回 `FLT_PREOP_COMPLETE` 这样更低的设备就不会收到Callback了

过滤驱动中有些经典的问题比如像重入。因为过滤驱动本身就在文件系统卷的栈里面，在驱动中调`ZwCreateFile`，请求是iomgr 取栈顶设备往下发的，回头还要经过自己

- minifilter 使用ECP `FLTMGR_TIOCTRL_ECP_GUID` 标记创建请求，里面保存当前filter 实例，然后在调用这些注册了的filter callback 时碰到对应的filter 就略过  
- sfilter 也可以使用ECP，还可以使用ObjectHint，就是`IoCreateFileEx` 可以传一个Driver Context，里面指定当次创建请求的TopDevice，创建过程 iomgr 就不会拿栈顶设备了  
- 还有其他起线程或是TopLevelIRP、影子卷之类的方法  

还有后续的连锁反应像minifilter 跨卷REPARSE 问题，在FltCreateFile 里面默认传入了ObjectHint，指向fltmgr 为当前物理卷分配的FDO。返回 REPARSE 后iomgr 重新解析路径，但获取到的是其他卷设备，在新设备的栈里可找不到一开始的FDO，就报错了

文件系统过滤广泛应用于透明加解密和杀毒软件、EDR等系统软件中。像对于杀毒软件，一般只关注打开/写入/创建Section 这些事件，在其中扫描文件内容。像EDR 类，就需要记录尽可能全的文件操作，更关注文件行为的收集

对于加解密软件，需要做的就比较复杂，一般来说加解密软件都需要支持对特定进程解密，这样不同的进程打开看到的是不同的内容。为了不影响系统缓存的工作，比如非授权进程中缓存密文但授权进程缓存明文，一般是选择自实现一层缓存

- 文件打开`IRP_MJ_CREATE`  
   - 打开目标文件，先读文件加密信息，生成一个自定义的Fcb  
   - 将目标文件的FileObject 保存下来，这个对象就是干净的磁盘上的文件，用来操作密文  
   - 将Fcb 设置为IRP 请求参数FileObject 的FsContext  
- 用户代码对FileObject 做读写动作  
   - 将自定义的Fcb 传入`CcInitializeCacheMap`，让缓存管理逻辑根据`AllocationSize` 生成`SharedCacheMap` 和DataSection  
   - 处理`CachedIO`，调用`CcCopyRead/Write`之类的函数自己处理缓存读写。另一个缓存的Paging IO 也是要处理的，因为默认会读到密文  
   - 处理`NonCachedIO`，从`FileObject->Fcb` 里面取干净的FileObject，生成一个读的IRP，发往下层设备，同时设置一个Completion Routine，读完还要解密。Write 的过程类似，把Buffer 加密后往干净的FileObject 里面写  
- 处理同步  
   - 这样能实现的效果是，非授权进程打开的FileObject 与授权进程的Fcb->FileObject 不用额外处理什么，用的都是系统缓存  
   - 授权进程访问文件时，过滤层必须响应所有IRP，因为返给用户的FileObject 里面Fcb/Ccb 是自定义的，只能用在缓存管理器这里，不能传给底下的文件系统设备，不识别。因此，对于会用到Cache 的函数，要自己实现逻辑，对于不用的，也要做代理帮忙Call 干净的FileObject  
      - 这一步非常繁琐  
   - 也可以选择不依托系统 Cc 的这些API 自己实现缓存，这就更繁琐了  

文件系统过滤现在也有许多应用在虚拟化上，虚拟化要达到的目的是重定向，这与文件加解密的逻辑有许多共通之处，不过重定向不需要自己实现一层缓存

- 文件打开`IRP_MJ_CREATE`  
   - 根据不同的策略，打开原始的和重定向后的 2个文件，如果都有的话  
   - 填充 IRP 中的参数FileObject，sfilter 可以继续用Fcb，minifilter 可以设置流句柄Context，这个FileObject 就像一个指针，可以指向原始文件，也可以指向重定向后的文件  
- 同步  
   - 处理所有IRP，然后根据策略处理像读/写/删这样的事件，与加解密类似，IRP 中返给用户的FileObject 只是个壳子，不能往下传递。到了需要`PassThrough`时，类似代理的作用，取真实的对象往下传  
   - 它跟加解密不同的地方比如一般它有2个文件，而且各自的修改逻辑是独立的。这里要处理File Sharing/文件权限/删除等这类文件行为的问题。这一层困难与繁琐的地方就在如何保持自己实现的行为与系统预期的一致  

对于文件系统过滤驱动来说，跳过还是比较简单的。ARK 可以在驱动中构建IRP，直接发往文件系统的底层设备，不取栈顶，就bypass 了

