$path_root  = split-path -Path $PSScriptRoot -Parent
$path_build = join-path $path_root  'build'
$exe        = join-path $path_build 'winapi_pfs.exe'

push-location $path_build
& $exe
pop-location
