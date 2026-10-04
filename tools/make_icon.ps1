# Renders the Dropper app icon (indigo rounded square + white droplet with a
# down-arrow) at every size Windows uses and packs them into one .ico.
# Run with Windows PowerShell: powershell -ExecutionPolicy Bypass -File tools\make_icon.ps1
param(
    [string]$OutIco = (Join-Path $PSScriptRoot "..\pc\Dropper.App\Assets\Dropper.ico"),
    [string]$OutPng = (Join-Path $PSScriptRoot "..\docs\icon-256.png")
)
Add-Type -AssemblyName System.Drawing

function New-IconBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.Clear([System.Drawing.Color]::Transparent)

    $s = [float]$size
    $r = $s * 0.22
    $bg = New-Object System.Drawing.Drawing2D.GraphicsPath
    $bg.AddArc(0, 0, 2 * $r, 2 * $r, 180, 90)
    $bg.AddArc($s - 2 * $r, 0, 2 * $r, 2 * $r, 270, 90)
    $bg.AddArc($s - 2 * $r, $s - 2 * $r, 2 * $r, 2 * $r, 0, 90)
    $bg.AddArc(0, $s - 2 * $r, 2 * $r, 2 * $r, 90, 90)
    $bg.CloseFigure()
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
        (New-Object System.Drawing.PointF 0, 0), (New-Object System.Drawing.PointF $s, $s),
        [System.Drawing.Color]::FromArgb(255, 0x6D, 0x66, 0xF6), [System.Drawing.Color]::FromArgb(255, 0x43, 0x38, 0xCA))
    $g.FillPath($grad, $bg)

    # Droplet: circle at the bottom, tangent curves up to a point at the top.
    $cx = $s * 0.5; $cy = $s * 0.60; $cr = $s * 0.235; $top = $s * 0.14
    $drop = New-Object System.Drawing.Drawing2D.GraphicsPath
    $drop.AddBezier($cx, $top, $cx + $cr * 0.35, $top + $cr * 0.9, $cx + $cr, $cy - $cr * 0.75, $cx + $cr, $cy)
    $drop.AddArc($cx - $cr, $cy - $cr, 2 * $cr, 2 * $cr, 0, 180)
    $drop.AddBezier($cx - $cr, $cy, $cx - $cr, $cy - $cr * 0.75, $cx - $cr * 0.35, $top + $cr * 0.9, $cx, $top)
    $drop.CloseFigure()
    $g.FillPath([System.Drawing.Brushes]::White, $drop)

    if ($size -ge 32) {
        # Down arrow cut into the droplet.
        $pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 0x4F, 0x46, 0xE5)), ([float]($s * 0.055))
        $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
        $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        $g.DrawLine($pen, $cx, $cy - $cr * 0.55, $cx, $cy + $cr * 0.45)
        $g.DrawLines($pen, [System.Drawing.PointF[]]@(
            (New-Object System.Drawing.PointF ($cx - $cr * 0.42), ($cy + $cr * 0.05)),
            (New-Object System.Drawing.PointF $cx, ($cy + $cr * 0.47)),
            (New-Object System.Drawing.PointF ($cx + $cr * 0.42), ($cy + $cr * 0.05))))
        $pen.Dispose()
    }
    $g.Dispose()
    return $bmp
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$pngs = @()
foreach ($sz in $sizes) {
    $bmp = New-IconBitmap $sz
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs += , $ms.ToArray()
    if ($sz -eq 256 -and $OutPng) {
        New-Item -ItemType Directory -Force -Path (Split-Path $OutPng) | Out-Null
        $bmp.Save($OutPng, [System.Drawing.Imaging.ImageFormat]::Png)
    }
    $bmp.Dispose()
}

New-Item -ItemType Directory -Force -Path (Split-Path $OutIco) | Out-Null
$fs = [System.IO.File]::Create($OutIco)
$w = New-Object System.IO.BinaryWriter $fs
$w.Write([UInt16]0); $w.Write([UInt16]1); $w.Write([UInt16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $sz = $sizes[$i]; $len = $pngs[$i].Length
    $dim = if ($sz -ge 256) { 0 } else { $sz }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([UInt16]1); $w.Write([UInt16]32); $w.Write([UInt32]$len); $w.Write([UInt32]$offset)
    $offset += $len
}
foreach ($p in $pngs) { $w.Write($p) }
$w.Close()
Write-Host "Wrote $OutIco and $OutPng"
