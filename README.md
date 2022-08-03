# Jumplists

`Windows`右键固定栏的应用程序时，会出现最近使用的项目，便于用户快速访问。这是`Windows`自动保存的信息，在电子取证时，可以作为相关的证据支撑。

`JumpList`文件符合一种[`OLE-CF`](https://github.com/libyal/libolecf/blob/main/documentation/OLE%20Compound%20File%20format.asciidoc)结构，即`Object Linking and Embedding(OLE) Compound File(CF)`。`Windows`中很多文件都符合这种结构，例如`ppt`，`word`，`excel`。在`Windows10`和`Windows 7`中，版本略有[差异](https://www.forensicfocus.com/forums/general/windows-10-and-jump-lists/#post-6576701)，这里以`Windows 10/11`为例。

## FileHeader

前`512`字节是文件头，文件头记录一些基本信息。

| 偏移量 |   大小    |                        描述                        |
| :----: | :-------: | :------------------------------------------------: |
|  `0`   |    `8`    | 文件幻术，通常为`\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1` |
|  `8`   |   `16`    |      `Class identifier (GUID)`，一般全部为`0`      |
|  `24`  |    `2`    |                      子版本号                      |
|  `26`  |    `2`    |                      主版本号                      |
|  `28`  |    `2`    |       字节序，`\xff\xfe`大端；`\xfe\xff`小端       |
|  `30`  |    `2`    |                 扇区(`sector`)大小                 |
|  `32`  |    `2`    |             小扇区(`mimi-sector`)大小              |
|  `34`  |    `2`    |                 `Reserved`保留字段                 |
|  `36`  |    `4`    |                 `Reserved`保留字段                 |
|  `40`  |    `4`    |                 `Reserved`保留字段                 |
|  `44`  |    `4`    |                用于`SAT`的扇区数量                 |
|  `48`  |    `4`    |              目录的起始扇区号(`SID`)               |
|  `52`  |    `4`    |                 `Reserved`保留字段                 |
|  `56`  |    `4`    |             标准流的大小(通常是`4096`)             |
|  `60`  |    `4`    |            `SSAT`的起始扇区号（`SID`）             |
|  `64`  |    `4`    |                用于`SSAT`的扇区数量                |
|  `68`  |    `4`    |            第一个`MSAT`的扇区号(`SID`)             |
|  `72`  |    `4`    |                  `MSAT`的扇区数量                  |
|  `76`  | `109 * 4` |            `MSAT`表，包含了`109`个`SID`            |

