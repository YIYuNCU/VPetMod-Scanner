package scan

// Severity 决定分值；任意一条 critical 直接判恶意。
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

func (s Severity) Score() int {
	switch s {
	case Critical:
		return 100
	case High:
		return 40
	case Medium:
		return 15
	case Low:
		return 5
	}
	return 0
}

type Rule struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
}

// 规则 ID 前缀：IOC=已知样本指纹，PX=PxBridge 家族结构特征，GEN=通用行为特征，MOD=MOD 包布局特征。
var Rules = []Rule{
	{"IOC-FILE-SHA256", Critical, "已知恶意文件",
		"文件整体 SHA256 命中已捕获样本。"},
	{"IOC-PE-BODY", Critical, "已知恶意 PE 主体",
		"去掉 overlay 后的哈希命中 PxBridge boot 加载器；该家族每次注入只改末尾 overlay，整文件哈希会变而主体不变。"},
	{"IOC-PE-TEXT", Critical, "已知恶意代码节",
		"`.text` 节哈希命中 PxBridge 载荷；载荷每次重新加密 .rdata/.data，代码节不变。"},
	{"PX-BOOT-EXPORT", Critical, "PxBridge boot 加载器",
		"导出目录里的原始 DLL 名为 boot_plain.dll，改文件名改不掉。"},
	{"PX-BOOT-TRAILER", Critical, "boot 加载器配置尾",
		"overlay 为 8 字节密钥 + 两个 16 字节定长 DLL 名 + 自描述长度，指明要手工映射的两个加密载荷。"},
	{"PX-PAYLOAD", Critical, "手工映射的加密载荷",
		"DLL 的导入/导出目录指向密文、数据节整段加密（熵接近 8），且带自描述长度的 overlay 尾：Windows 加载器无法直接加载，只能由 boot 解密后手工映射执行。"},
	{"PX-PAYLOAD-TRAILER", Critical, "加密载荷自描述配置尾",
		"overlay 恰 108 字节、尾标记 0x68，且尾部记录的两块解密区域与自身 .rdata/.data 节的 VA/RawSize 精确对齐——boot 侧 44 字节 trailer 的载荷侧对应物，整文件改哈希也变不掉。"},
	{"PX-JS-INJECT", Critical, "载荷代码节含浏览器注入标记",
		"明文 .text 节里出现 __pxGate / self.__pxA 等注入脚本片段（movabs 立即数形式），指向对浏览器 / Steam 社区页的会话与登录态注入——无需解密 .rdata 即可从明文代码节直接取证。"},
	{"PX-ARTIFACT-MARKERS", Critical, "PxBridge 注入/篡改工件标记",
		"同一文件里命中 >=3 个家族专有标记且其中至少一个是强标记（/*px:b*/、_local_patch_backup、px_msgpoll.js、[SteamUI sp] 等，ASCII 与 UTF-16LE 两种编码都查）。**跨节扫描**：明态编译载荷把这些标记放在 .rdata，只搜 .text 会整体漏掉。"},
	{"PX-ARTIFACT-MARKERS-WEAK", Low, "疑似 PxBridge 工件标记（弱）",
		"命中 1~2 个家族标记，或只命中弱标记（/gate.php、api/messages、ConnectCache）。仅作检索线索，不足以定性。"},
	// 注意：曾有一条 PX-PACKER-FPTABLE（全零 .fptable 节）。**已删除，不要加回来。**
	// .fptable 不是打包器的占位节，而是 Universal CRT 的函数指针缓存节：
	//   #pragma data_seg(push, almostro, ".fptable")
	//   #pragma bss_seg (push, almostro, ".fptable")
	//   static void* function_pointers[function_id_count];     // ucrt/internal/winapi_thunks.cpp
	// Windows SDK >= 10.0.26100 起，任何链接 UCRT 的 PE 都会带它；因为是 bss_seg，内容全零、
	// raw_size 一页对齐（0x200）、virt_size = 指针数 x 指针宽度（x64 32x8=0x100，x86 32x4=0x80）。
	// 工坊 134 个 MOD 语料实测：3 个正常 MOD 的 VPetLLM.SecureCommunication.dll 命中，
	// 并把其中一个从 clean(20) 抬到 suspicious(35) —— 典型的"看着像指纹、其实是编译器产物"。
	// 家族组件确实也带 .fptable，但那只说明它们同样是新 SDK 编的，与家族归属无关。
	{"PX-STUB", Critical, "PxBridge 插件加载器桩",
		"VPet 插件 DLL 内含 PxBridge/SidecarFn/FindSidecarDll 等家族类型名，或 px-orig- 字符串。"},
	{"PX-SIDECAR", Critical, ".px_sidecar 注入清单",
		"注入工具写入的清单文件，记录 boot/mod1/mod2/orig 文件名。"},
	// 只给 medium：内嵌 Harmony/MonoMod 的正常 MOD 也会同时引用这三个 API（实测工坊 3022006959）。
	// 单独命中不足以判可疑，要和 ORIG-WRAP / NATIVE-DIR 等叠加才升级。
	{"GEN-STUB-NATIVE-EXEC", Medium, "插件动态执行原生代码",
		"MainPlugin 子类同时引用 LoadLibrary + GetProcAddress + Marshal.GetDelegateForFunctionPointer：在 VPet 进程里取原生函数指针直接调用。"},
	{"GEN-HELPER-NATIVE-EXEC", Medium, "辅助程序集按名加载原生 DLL",
		"**非插件入口**（无 MainPlugin）的托管程序集同时引用 LoadLibrary + GetProcAddress + GetDelegateForFunctionPointer，并且把某个非自身的 *.dll 名字作为字符串常量。跨程序集的原生加载器：真正干活的 DLL 不继承 MainPlugin，原先在 MainPlugin 检查之后提前返回会整条漏掉（实测 鸭科夫样本 CalcBridge.dll）。"},
	{"GEN-STUB-REFLECT-ORIG", High, "插件包装原插件",
		"插件代码里硬编码 *.orig.dll 并反射加载它——原插件被挪走、由包装器转发，外观功能正常。"},
	{"GEN-PAYLOAD-NOIMPORT", High, "导入表不可读的高熵 DLL",
		"DLL 没有可解析的导入表且存在熵 ≥ 7.9 的数据节，典型的加密/手工映射载荷。"},
	{"GEN-OVERLAY-TRAILER", Medium, "自描述 overlay 尾",
		"overlay 最后 4 字节恰好等于 overlay 长度 - 4，属于自定义打包格式。"},
	{"MOD-ORIG-WRAP", High, "原插件被移入 lib/*.orig.dll",
		"plugin/lib 下存在 X.orig.dll 且 plugin 下有同名 X.dll，符合注入器的替换手法。"},
	{"MOD-NATIVE-DIR", Medium, "MOD 根目录存在 native/ 原生 DLL",
		"VPet 不会加载 MOD 根下的 native 目录，这些 DLL 只能被插件代码手工加载。"},
	{"MOD-INJECT-TOOLING", Medium, "注入/上传工具残留",
		"MOD 内脚本引用 prepare_vpet_mod.py 或 VpetOneClick，属于该批样本的打包上传流水线。"},
	{"MOD-SCRIPT", Low, "MOD 内含脚本文件",
		"MOD 包里带 .bat/.cmd/.ps1/.py/.vbs 等脚本，VPet 不需要这些文件。"},
	{"NET-ENDPOINT", Low, "外联地址（静态提取）",
		"托管插件里硬编码的 URL/域名/IP。VPet 插件联网本身不一定恶意，但这是它会连的外部地址，需人工确认用途（尤其把对话/数据转发到第三方中转的插件）。"},
	{"NET-EMBEDDED-SECRET", Medium, "插件内嵌密钥/令牌",
		"插件里硬编码了 API Key / Bearer 令牌等机密。共享密钥常见于'免费公益中转'类插件——你的请求与数据经不可控第三方，且密钥可能随时失效或被滥用。"},
	{"NET-KNOWN-C2", Critical, "外联已知 PxBridge C2",
		"地址命中 PxBridge 载荷解密证实的 C2（bvdpp.top：Steal JWT/凭据端点 /ey/2.php、/vdf/2.php，SteamUI 注入接口 /gate.php、/steamhelper*）。原始样本里这些在加密节内静态不可见；哪份文件明文出现，要么是新变种漏加密，要么是配套投放物。"},
}

var ruleIndex = func() map[string]Rule {
	m := make(map[string]Rule, len(Rules))
	for _, r := range Rules {
		m[r.ID] = r
	}
	return m
}()

// 以下 IOC 来自 Test/ 下三个样本：
//   3803401951                         刮刮卡 v1.0.4 (VPet.Plugin.ScratchCard)
//   depot_1920960_3678898894967785038  SmartPet
//   depot_1920960_4637760495230589419  天籁之音！(VPet.Plugin.TianLaiZhiYin)

var iocFileSHA256 = map[string]string{
	"80741f064cc493f6bcfb13a1c9c96176fe160077750343335d5ea7769f4220bc": "PxBridge stub (ScratchCard)",
	"df0f952428fca45e07443ddf7a582b4470705047e794d2307800d7e0b7224601": "PxBridge stub (SmartPet)",
	"167b17f9ab024fcdd7e776b4bc58233a7dea66724c2f66659f0d101a405e92af": "PxBridge stub (TianLaiZhiYin)",
	"fdad4cb139ad9d0e90c3c792502d3b471ee5d2dd86c61fc113df1bd63171c181": "boot (asset_4g.dll)",
	"3454551b2fd85f64cdfa336799635034a3b0bd4411fdd50c18de2ce0a6b40dfa": "boot (pluginr78.dll)",
	"00fddce89e481c1997336b0a33105914cd88f3691f9252f218cb61e0659abdb8": "boot (helper_5e.dll)",
	"1d7b4e03ad1cadb430981a43d015e455cf36e69350984236205a8d80a32d52e9": "mod1 (gamev47.dll)",
	"a6b8d19099935345c4c9a5af741bd306f8499b255a1f8d36ed323286a7303e23": "mod1 (utilpro9.dll)",
	"992230fe215fb684ea5d8079cb8d303f55c92ede4314094d3bd2d80870f8217e": "mod1 (assetplu8.dll)",
	"ec83b7e95ce6311feeb4c1a991a9dd68df2ad359c3af0808df5e4551367fb4be": "mod2 (msgame2.dll)",
	"92af8aa27fa192187f6e9dec03fd2f4b9f6015c0e352cfd10133f33134bdd772": "mod2 (play27.dll)",
	"ae2719b116f1227157342f52a48f1119091b82f9a0fabc8dd0c9c76fa299f0d8": "mod2 (plugin_8b.dll)",
	// 天籁之音(3803426816) 载荷的静态解密分析副本（另一位开发者产出）。不是野外分发形态，
	// 但若被误传到审核服务须认出：内容与恶意载荷等价，不能当普通文件放行。
	"abc60cde023e6e521033fd0b35a723a85e49a07c55cfe4ed30afec27574dea2d": "PxBridge payload decoded (assetplu8)",
	"9c22136b37d1c28eef63f5c5ff29abdf52d24ce3505c3cfa7f1f2b813538ecb5": "PxBridge payload decoded (plugin_8b)",
	// 鸭科夫假红信mod（SteamCFyinxiao.dll）：同一家族的**明态编译**投放物，跨游戏投放。
	// 无 overlay 尾部、无 boot、导入表可读，结构规则只有 PX-JS-INJECT / PX-ARTIFACT-MARKERS 能命中，
	// 所以整文件哈希必须留着兜底。
	"a413ff6010241c8a80d098eb620c1796247f01d3f41f18042d4d52bc1b0e29d7": "PxBridge plaintext SteamUI tamper (SteamCFyinxiao.dll)",
}

// 已证实的 PxBridge C2（3803426816 载荷解密后从 .rdata 提取；原始样本中在加密节内）。
// host 精确匹配或子域名匹配；命中即 NET-KNOWN-C2。
// 同时用于**原始字节扫描**（ASCII + UTF-16LE）：载荷在磁盘上只存裸 host，
// URL 是运行时用 "https://%s/..." 拼出来的，只靠 urlRe 永远匹配不到。
var knownC2Hosts = map[string]string{
	"bvdpp.top":    "Steal JWT/凭据外传 + SteamUI 注入引导（/ey/2.php /vdf/2.php /gate.php /steamhelper*）",
	"hhfyuxuz.top": "同族第二套 C2（跨游戏投放包 鸭科夫假红信mod/SteamCFyinxiao.dll）：/gate.php 远程开关 + /steamhelper* 页面引导；不含 /ey /vdf 窃密端点。打下 bvdpp.top 不会让这个包失效",
}

// PxBridge 注入/篡改工件的字符串标记。跨节扫描（不限 .text），ASCII 与 UTF-16LE 都查。
//
// 分强弱两档的理由：弱标记（/gate.php、api/messages、ConnectCache）在正常 Steam 生态里
// 也可能出现，命中少数几条不足以定性；判定要求「>=3 个命中且至少 1 个强标记」。
// 强标记是这套注入器的自有命名，实测在明态编译载荷里全部出现。
var (
	pxArtifactStrong = []string{
		"/*px:b*/", "/*px:e*/", "_local_patch_backup", "px_msgpoll.js",
		"[SteamUI sp]", "m_nUnviewedNotifications", "desktop_toast_default.wav", "px_mod.log",
	}
	pxArtifactWeak = []string{
		"/gate.php", "/steamhelper", "api/messages", "ConnectCache",
	}
)

// artifactMinHits / artifactMinStrong：判定 PX-ARTIFACT-MARKERS（critical）的阈值。
const (
	artifactMinHits   = 3
	artifactMinStrong = 1
)

var iocBodySHA256 = map[string]string{
	"acff7686e83fe2a537da59af2f02ddcf9aaf776cad3a17b97e228a7550e81f2c": "PxBridge boot_plain.dll",
}

var iocTextSHA256 = map[string]string{
	"61608a0e5368edb561de5bd8bf4d45dcf88e73368983e8ee00c9644a2214c41c": "PxBridge boot_plain.dll",
	"ff54c00da7852f2f3c3ef00c2a3ac081a8e000ddbab47f4508b421e415689309": "PxBridge payload mod1",
	"49e73cfa1d40dc1e79ebd9822f43decf4884145eb5caabe040a53dcb4649b018": "PxBridge payload mod2",
}

// 加载器桩里的家族类型/方法名（#Strings 堆）。
var pxStubMarkers = []string{"PxBridge", "PxVpetBridge", "SidecarFn", "FindSidecarDll", "WrapperMeta", "GetProcAddressOrdinal"}

type IOCSet struct {
	FileSHA256 map[string]string `json:"file_sha256"`
	BodySHA256 map[string]string `json:"pe_body_sha256"`
	TextSHA256 map[string]string `json:"pe_text_sha256"`
	StubNames  []string          `json:"dotnet_stub_markers"`
}

func IOCs() IOCSet {
	return IOCSet{iocFileSHA256, iocBodySHA256, iocTextSHA256, pxStubMarkers}
}
