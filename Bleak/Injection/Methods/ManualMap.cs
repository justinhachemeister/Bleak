using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Bleak.Injection.Interfaces;
using Bleak.Injection.Objects;
using Bleak.Injection.Tools;
using Bleak.Native;
using Bleak.Shared;

namespace Bleak.Injection.Methods
{
    internal class ManualMap : IInjectionMethod
    {
        private readonly InjectionTools _injectionTools;

        private readonly InjectionWrapper _injectionWrapper;

        private IntPtr _localDllAddress;

        private IntPtr _remoteDllAddress;

        public ManualMap(InjectionWrapper injectionWrapper)
        {
            _injectionTools = new InjectionTools(injectionWrapper);

            _injectionWrapper = injectionWrapper;
        }

        public IntPtr Call()
        {
            // Store the DLL bytes in a buffer

            var dllBufferHandle = GCHandle.Alloc(_injectionWrapper.DllBytes.Clone(), GCHandleType.Pinned);

            _localDllAddress = dllBufferHandle.AddrOfPinnedObject();

            // Build the import table of the DLL in the local process

            BuildImportTable();

            // Allocate memory for the DLL in the remote process

            var peHeaders = _injectionWrapper.PeParser.GetPeHeaders();

            var preferredBaseAddress = _injectionWrapper.RemoteProcess.IsWow64
                                     ? _injectionWrapper.PeParser.GetPeHeaders().NtHeaders32.OptionalHeader.ImageBase
                                     : _injectionWrapper.PeParser.GetPeHeaders().NtHeaders64.OptionalHeader.ImageBase;

            var dllSize = _injectionWrapper.RemoteProcess.IsWow64
                        ? peHeaders.NtHeaders32.OptionalHeader.SizeOfImage
                        : peHeaders.NtHeaders64.OptionalHeader.SizeOfImage;

            try
            {
                _remoteDllAddress = _injectionWrapper.MemoryManager.AllocateVirtualMemory((IntPtr) preferredBaseAddress, (int) dllSize);
            }

            catch (Win32Exception)
            {
                _remoteDllAddress = _injectionWrapper.MemoryManager.AllocateVirtualMemory((int) dllSize);
            }

            // Relocate the DLL in the local process

            RelocateImage();

            // Map the sections of the DLL into the remote process

            MapSections();

            // Map the headers of the DLL into the remote process

            MapHeaders();

            // Call any TLS callbacks

            CallTlsCallbacks();

            // Call the entry point of the DLL

            var dllEntryPointAddress = _injectionWrapper.RemoteProcess.IsWow64
                                     ? _remoteDllAddress.AddOffset(peHeaders.NtHeaders32.OptionalHeader.AddressOfEntryPoint)
                                     : _remoteDllAddress.AddOffset(peHeaders.NtHeaders64.OptionalHeader.AddressOfEntryPoint);

            if (dllEntryPointAddress != _remoteDllAddress)
            {
                CallEntryPoint(dllEntryPointAddress);
            }

            dllBufferHandle.Free();

            return _remoteDllAddress;
        }

        private void BuildImportTable()
        {
            var importedFunctions = _injectionWrapper.PeParser.GetImportedFunctions();

            if (importedFunctions.Count == 0)
            {
                // The DLL has no imported functions

                return;
            }

            // Get the API set mappings

            var apiSetMappings = GetApiSetMappings();

            // Resolve the DLL of any functions imported from a virtual DLL

            foreach (var importedFunction in importedFunctions)
            {
                if (importedFunction.Dll.StartsWith("api-ms"))
                {
                    importedFunction.Dll = apiSetMappings.Find(apiSetMapping => apiSetMapping.VirtualDll.Equals(importedFunction.Dll, StringComparison.OrdinalIgnoreCase)).MappedToDll;
                }
            }

            // Group the imported functions by the DLL they reside in

            var groupedFunctions = importedFunctions.GroupBy(importedFunction => importedFunction.Dll).ToList();

            // Ensure the dependencies of the DLL are loaded in the remote process

            var systemFolderPath = _injectionWrapper.RemoteProcess.IsWow64
                                 ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)
                                 : Environment.GetFolderPath(Environment.SpecialFolder.System);

            foreach (var dll in groupedFunctions)
            {
                if (!_injectionWrapper.RemoteProcess.Modules.Any(module => module.Name.Equals(dll.Key, StringComparison.OrdinalIgnoreCase)))
                {
                    // Load the DLL into the remote process

                    using (var injector = new Injector(InjectionMethod.CreateRemoteThread, _injectionWrapper.RemoteProcess.Process.Id, Path.Combine(systemFolderPath, dll.Key)))
                    {
                        injector.InjectDll();
                    }

                    _injectionWrapper.RemoteProcess.Refresh();
                }
            }

            foreach (var importedFunction in groupedFunctions.SelectMany(dll => dll.Select(importedFunction => importedFunction)))
            {
                // Get the address of the imported function

                IntPtr importedFunctionAddress;

                importedFunctionAddress = importedFunction.Name is null
                                        ? _injectionWrapper.RemoteProcess.GetFunctionAddress(importedFunction.Dll, importedFunction.Ordinal)
                                        : _injectionWrapper.RemoteProcess.GetFunctionAddress(importedFunction.Dll, importedFunction.Name);

                // Write the imported function into the local process

                Marshal.WriteIntPtr(_localDllAddress.AddOffset(importedFunction.Offset), importedFunctionAddress);
            }
        }

        private void CallEntryPoint(IntPtr entryPointAddress)
        {
            // Call the entry point of the DLL or TLS callback with DllProcessAttach in the remote process

            _injectionTools.CallRemoteFunction(entryPointAddress, (ulong) _remoteDllAddress, Constants.DllProcessAttach, 0);
        }

        private void CallTlsCallbacks()
        {
            foreach (var tlsCallback in _injectionWrapper.PeParser.GetTlsCallbacks())
            {
                CallEntryPoint(_remoteDllAddress.AddOffset(tlsCallback.Offset));
            }
        }

        private List<ApiSetMapping> GetApiSetMappings()
        {
            var apiSetMappings = new List<ApiSetMapping>();

            // Read the namespace of the API set

            var apiSetDataAddress = _injectionWrapper.RemoteProcess.IsWow64
                                  ? (IntPtr) _injectionWrapper.RemoteProcess.GetWow64Peb().ApiSetMap
                                  : (IntPtr) _injectionWrapper.RemoteProcess.GetPeb().ApiSetMap;

            var apiSetNamespace = _injectionWrapper.MemoryManager.ReadVirtualMemory<Structures.ApiSetNamespace>(apiSetDataAddress);

            for (var index = 0; index < (int) apiSetNamespace.Count; index += 1)
            {
                // Read the namespace entry

                var namespaceEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<Structures.ApiSetNamespaceEntry>(apiSetDataAddress.AddOffset(apiSetNamespace.EntryOffset + Marshal.SizeOf<Structures.ApiSetNamespaceEntry>() * index));

                // Read the name of the namespace entry

                var namespaceEntryNameBytes = _injectionWrapper.MemoryManager.ReadVirtualMemory(apiSetDataAddress.AddOffset(namespaceEntry.NameOffset), (int) namespaceEntry.NameLength);

                var namespaceEntryName = string.Concat(Encoding.Unicode.GetString(namespaceEntryNameBytes), ".dll");

                // Read the value entry that the namespace entry maps to

                var valueEntry = _injectionWrapper.MemoryManager.ReadVirtualMemory<Structures.ApiSetValueEntry>(apiSetDataAddress.AddOffset(namespaceEntry.ValueOffset));

                // Read the name of the value entry

                var valueEntryNameBytes = _injectionWrapper.MemoryManager.ReadVirtualMemory(apiSetDataAddress.AddOffset(valueEntry.ValueOffset), (int) valueEntry.ValueCount);

                var valueEntryName = Encoding.Unicode.GetString(valueEntryNameBytes);

                apiSetMappings.Add(new ApiSetMapping(valueEntryName, namespaceEntryName));
            }

            return apiSetMappings;
        }

        private static Enumerations.MemoryProtection GetSectionProtection(Enumerations.SectionCharacteristics sectionCharacteristics)
        {
            // Determine the protection of the section

            var sectionProtection = default(Enumerations.MemoryProtection);

            if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryNotCached))
            {
                sectionProtection |= Enumerations.MemoryProtection.NoCache;
            }

            if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryExecute))
            {
                if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryRead))
                {
                    if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryWrite))
                    {
                        sectionProtection |= Enumerations.MemoryProtection.ExecuteReadWrite;
                    }

                    else
                    {
                        sectionProtection |= Enumerations.MemoryProtection.ExecuteRead;
                    }
                }

                else if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryWrite))
                {
                    sectionProtection |= Enumerations.MemoryProtection.ExecuteWriteCopy;
                }

                else
                {
                    sectionProtection |= Enumerations.MemoryProtection.Execute;
                }
            }

            else
            {
                if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryRead))
                {
                    if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryWrite))
                    {
                        sectionProtection |= Enumerations.MemoryProtection.ReadWrite;
                    }

                    else
                    {
                        sectionProtection |= Enumerations.MemoryProtection.ReadOnly;
                    }
                }

                else if (sectionCharacteristics.HasFlag(Enumerations.SectionCharacteristics.MemoryWrite))
                {
                    sectionProtection |= Enumerations.MemoryProtection.WriteCopy;
                }

                else
                {
                    sectionProtection |= Enumerations.MemoryProtection.NoAccess;
                }
            }

            return sectionProtection;
        }

        private void MapHeaders()
        {
            // Read the PE headers of the DLL

            var headerSize = _injectionWrapper.RemoteProcess.IsWow64
                           ? _injectionWrapper.PeParser.GetPeHeaders().NtHeaders32.OptionalHeader.SizeOfHeaders
                           : _injectionWrapper.PeParser.GetPeHeaders().NtHeaders64.OptionalHeader.SizeOfHeaders;

            var headerBytes = new byte[headerSize];

            Marshal.Copy(_localDllAddress, headerBytes, 0, headerBytes.Length);

            // Write the PE headers into the remote process

            _injectionWrapper.MemoryManager.WriteVirtualMemory(_remoteDllAddress, headerBytes);

            _injectionWrapper.MemoryManager.ProtectVirtualMemory(_remoteDllAddress, (int) headerSize, Enumerations.MemoryProtection.ReadOnly);
        }

        private void MapSections()
        {
            foreach (var section in _injectionWrapper.PeParser.GetPeHeaders().SectionHeaders)
            {
                if (section.SizeOfRawData == 0)
                {
                    continue;
                }

                // Get the data of the section

                var sectionDataAddress = _localDllAddress.AddOffset(section.PointerToRawData);

                var sectionData = new byte[section.SizeOfRawData];

                Marshal.Copy(sectionDataAddress, sectionData, 0, (int) section.SizeOfRawData);

                // Write the section into the remote process

                var sectionAddress = _remoteDllAddress.AddOffset(section.VirtualAddress);

                _injectionWrapper.MemoryManager.WriteVirtualMemory(sectionAddress, sectionData);

                // Adjust the protection of the section

                var sectionProtection = GetSectionProtection(section.Characteristics);

                _injectionWrapper.MemoryManager.ProtectVirtualMemory(sectionAddress, (int) section.SizeOfRawData, sectionProtection);
            }
        }

        private void RelocateImage()
        {
            var baseRelocations = _injectionWrapper.PeParser.GetBaseRelocations();

            if (baseRelocations.Count == 0)
            {
                // No relocations need to be applied

                return;
            }

            var preferredBaseAddress = _injectionWrapper.RemoteProcess.IsWow64
                                     ? _injectionWrapper.PeParser.GetPeHeaders().NtHeaders32.OptionalHeader.ImageBase
                                     : _injectionWrapper.PeParser.GetPeHeaders().NtHeaders64.OptionalHeader.ImageBase;

            // Calculate the preferred base address delta

            var delta = (long) _remoteDllAddress - (long) preferredBaseAddress;

            if (delta == 0)
            {
                // The DLL is loaded at its preferred base address and no relocations need to be applied

                return;
            }

            foreach (var baseRelocation in baseRelocations)
            {
                // Calculate the base address of the relocation block

                var relocationBlockAddress = _localDllAddress.AddOffset(baseRelocation.Offset);

                foreach (var relocation in baseRelocation.Relocations)
                {
                    // Calculate the address of the relocation

                    var relocationAddress = relocationBlockAddress.AddOffset(relocation.Offset);

                    switch (relocation.Type)
                    {
                        case Enumerations.RelocationType.HighLow:
                        {
                            // Perform the relocation

                            var relocationValue = Marshal.ReadInt32(relocationAddress) + (int) delta;

                            Marshal.WriteInt32(relocationAddress, relocationValue);

                            break;
                        }

                        case Enumerations.RelocationType.Dir64:
                        {
                            // Perform the relocation

                            var relocationValue = Marshal.ReadInt64(relocationAddress) + delta;

                            Marshal.WriteInt64(relocationAddress, relocationValue);

                            break;
                        }
                    }
                }
            }
        }
    }
}