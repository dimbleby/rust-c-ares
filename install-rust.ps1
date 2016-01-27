param([string]$channel=${env:channel}, [string]$target=${env:target})

$downloadUrl = "https://static.rust-lang.org/dist/"
$manifest = "${env:Temp}\channel-rust-${channel}"
Start-FileDownload "${downloadUrl}channel-rust-${channel}" -FileName "${manifest}"

$match = Get-Content "${manifest}" | Select-String -pattern "${target}.exe" -simplematch
$installer = $match.line

Start-FileDownload "${downloadUrl}${installer}" -FileName "${env:Temp}\${installer}"

$installDir = "C:\Program Files (x86)\Rust"
&"${env:Temp}\${installer}" /VERYSILENT /NORESTART /DIR="${installDir}" | Write-Output
$env:Path += ";${installDir}\bin"

rustc -V
cargo -V
