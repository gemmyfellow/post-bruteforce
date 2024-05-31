# post-bruteforce

Create a simple dictionary attack against a post route using CLI.


## How to use

<img src="/example.png"></img>

You can install a precompiled version <a href="https://github.com/cobs0n/post-bruteforce/releases/tag/cbrute">here</a>, simply open commands prompts in the same directory as the exe and paste the command simillar to this, the first argument would be the username and the second argument would be the post route url. 

```
CBRute.exe target https://example.com dict.txt
```


## Build from source

If you would like to build from source, you'd first need to have a c++ compiler and curl installed. <a href="https://stackoverflow.com/questions/53861300/how-do-you-properly-install-libcurl-for-use-in-visual-studio-2017">Heres </a> a tutorial on how you can install curl. Afterwards just download the cbrute.cpp and build.

You can use make to build the project
```
make
```

