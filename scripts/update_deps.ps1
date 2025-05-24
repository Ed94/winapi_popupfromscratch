$path_root  = split-path -Path $PSScriptRoot -Parent
$path_build = join-path $path_root 'build'
$path_code  = join-path $path_root 'code'

$devshell           = Join-Path $PSScriptRoot 'helpers/devshell.ps1'
$vendor_toolchain   = Join-Path $PSScriptRoot 'helpers/vendor_toolchain.ps1'

#region Arguments
       $vendor       = $null
       $release      = $null

[array] $vendors = @( "clang", "msvc" )

# This is a really lazy way of parsing the args, could use actual params down the line...

if ( $args ) { $args | ForEach-Object {
	switch ($_){
		{ $_ -in $vendors }   { $vendor       = $_; break }
		"verbose"			  { $verbose      = $true }
		"release"             { $release      = $true }
		"debug"               { $release      = $false }
	}
}}
#endregion Arguments

if ( $vendor -eq $null ) {
	write-host "No vendor specified, assuming clang available"
	$compiler = "clang"
}

if ( $release -eq $null ) {
	write-host "No build type specified, assuming debug"
	$release = $false
}
elseif ( $release -eq $false ) {
	$debug = $true
}
else {
	$optimize = $true
}

. $vendor_toolchain

Write-Host "Building Zydis static library..."
$path_zydis     = join-path $path_code      'zydis'
$path_zydis_lib = join-path $path_zydis     'lib'
$path_zydis_src = join-path $path_zydis_lib 'src'

push-location $path_zydis_lib
$unit = join-path $path_zydis_src 'zydis.c'
$bin  = join-path $path_zydis_lib 'zydis.lib'

$includes = $path_zydis_lib

$compiler_args = @()
$compiler_args += $flag_all_c
$compiler_args += ($flag_define + 'ZYDIS_STATIC_BUILD')

$linker_args = @()
$linker_args += $flag_link_win_subsystem_console

$result = build $path_zydis_lib $includes $compiler_args $linker_args $unit $bin
pop-location
