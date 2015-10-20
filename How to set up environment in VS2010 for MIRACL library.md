This file tells you how to set up VS2010 for using MIRACL library to do AES encryption. Please follow steps below. 

1. Download MIRACL-.zip file from our github repository here. https://github.com/C00IHandLuke/CPEN442VPN/blob/master/MIRACL-.zip

2. Unzip MIRACL-.zip

3. Create a new win32 console program project in your VS (here, we use VS2010), let's name it AES, then under "additional options", choose "empty project".

4. Add "miracl.lib", which you can find in "lib" folder in MIRACL-, under  Resource Files category in your AES project.

5. Add "miracl.h", which you can find in "include" folder in MIRACL-, under Header Files category in your AES project.

6. Add "mraes.c", which you can find in "source" folder in MIRACL-, under Source Files category  in your AES project.

7. Find Project Properties, then open it. Under "Configuration properties", find "Linker" ---->"Input"---->"Additional dependencies"---->write "miracl.lib" in "Additional dependencies"

8. Still in "Configuration properties" page, find "Linker" again ---->"Input"---->"Ignore specific default dependencies" ---->write "LIBC.lib" here

9. Then find "VC++ directories"---->"Include directories"---->find the "include" folder under your MIRACL- folder, then add its path vaule here

10. "VC++ directories"---->"Library directories"---->find the "lib" folder under your MIRACL- folder, then add its path value here

Here, you almost done. You can try to run and test our AES_done.cpp now.