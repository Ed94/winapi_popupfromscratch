# WinAPI Popup From Scratch

Little exercise on making a PE from scratch with a PE encoder & zydis for the x86-64 encoding

* [scripts/build.ps1](./scripts/build.ps1) will build [code/winapi_pfs.odin](./code/winapi_pfs.odin)
* [scripts/update_deps.ps1](./scripts/update_deps.ps1) will build the zydis.lib that [zydis.odin](./code/zydis/zydis.odin) depends on

In powershell:

```ps1
.\scripts\build
# then
.\scripts\run # to execute the exercise program.
```

## Notable Repos

[projectxiel/pe-from-scratch](https://github.com/projectxiel/pe-from-scratch)  
[jonomango/pe-builder](https://github.com/jonomango/pe-builder)  
[BackupGGCode/portable-executable-library](https://github.com/BackupGGCode/portable-executable-library)  
[eladraz/pe](https://github.com/eladraz/pe)  
[lief-project/LIEF](https://github.com/lief-project/LIEF)

## Articles

[An In-Depth Look into the Win2 Portable Executable File Format](https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail)

* [Part 2](https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/march/inside-windows-an-in-depth-look-into-the-win32-portable-executable-file-format-part-2)

[PE Format Poster](https://www.openrce.org/reference_library/files/reference/PE%20Format.pdf)  
[A dive into the PE file format](https://0xrick.github.io/win-internals/pe1/)  
[Portable Executable File Format](https://blog.kowalczyk.info/articles/pefileformat.html)

## Docs

[MSDN: PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format?redirectedfrom=MSDN)  
[doc.zydis](https://doc.zydis.re/v4.1.1/html/)

* [Encoder](https://doc.zydis.re/v4.1.1/html/group__encoder)

## Books

[Linkers & Loaders](https://linker.iecc.com)
