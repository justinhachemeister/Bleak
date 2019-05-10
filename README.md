## Bleak 

[![Build status](https://ci.appveyor.com/api/projects/status/5avg8vtr9kep050a?svg=true)](https://ci.appveyor.com/project/Akaion/bleak)

A Windows native DLL injection library written in C# that supports several methods of injection.

----

### Injection Methods

* CreateRemoteThread
* ManualMap
* ThreadHijack

### Injection Extensions

* Eject DLL
* Hide DLL From PEB
* Randomise DLL Headers

### Features

* x86 and x64 injection
* Optional randomise DLL name

----

### Installation

* Download and install Bleak using [NuGet](https://www.nuget.org/packages/Bleak)

----

### Usage Example

The example below describes a basic implementation of the library.

```csharp
using Bleak;

var injector = new Injector(InjectionMethod.CreateRemoteThread, "processName", "pathToDll");

// Inject the DLL into the process using the CreateRemoteThread method

injector.InjectDll();

// Randomise the PE headers of the DLL

injector.RandomiseDllHeaders();
```

Full documentation for the library can be found [here](https://akaion.github.io/repositories/bleak.html) 

----

### Contributing

Pull requests are welcome. 

For large changes, please open an issue first to discuss what you would like to add.
