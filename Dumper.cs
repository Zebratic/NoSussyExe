using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

namespace NoSussyExe.Dumper
{
    public class Dumper
    {
		/* 
		 *  Some of the following code is rewritten from https://github.com/CodeCracker-Tools/MegaDumper
		 *  Thanks to CodeCracker Tools for the Dumping mechanism
		 */

		public string DumpLog { get; set; }

		[DllImport("Kernel32.dll")]
		public static extern bool ReadProcessMemory
		(
			IntPtr hProcess,
			IntPtr lpBaseAddress,
			byte[] lpBuffer,
			UInt32 nSize,
			ref UInt32 lpNumberOfBytesRead
		);


		[DllImport("Kernel32.dll")]
		public static extern bool ReadProcessMemory
		(
			IntPtr hProcess,
			uint lpBaseAddress,
			byte[] lpBuffer,
			UInt32 nSize,
			ref UInt32 lpNumberOfBytesRead
		);

		public enum ProcessAccess : int
		{
			AllAccess = CreateThread | DuplicateHandle | QueryInformation | SetInformation | Terminate | VMOperation | VMRead | VMWrite | Synchronize,
			CreateThread = 0x2,
			DuplicateHandle = 0x40,
			QueryInformation = 0x400,
			SetInformation = 0x200,
			Terminate = 0x1,
			VMOperation = 0x8,
			VMRead = 0x10,
			VMWrite = 0x20,
			Synchronize = 0x100000
		}

		[StructLayout(LayoutKind.Sequential)]
		public struct SYSTEM_INFO
		{
			public uint dwOemId;
			public uint dwPageSize;
			public uint lpMinimumApplicationAddress;
			public uint lpMaximumApplicationAddress;
			public uint dwActiveProcessorMask;
			public uint dwNumberOfProcessors;
			public uint dwProcessorType;
			public uint dwAllocationGranularity;
			public uint dwProcessorLevel;
			public uint dwProcessorRevision;
		}

		[DllImport("kernel32")]
		public static extern void GetSystemInfo(ref SYSTEM_INFO pSI);

		[DllImport("kernel32.dll")]
		static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Int32 bInheritHandle, UInt32 dwProcessId);

		[DllImport("kernel32.dll", SetLastError = true)]
		[return: MarshalAs(UnmanagedType.Bool)]
		static extern bool CloseHandle(IntPtr hObject);


		private const uint PROCESS_TERMINATE = 0x0001;
		private const uint PROCESS_CREATE_THREAD = 0x0002;
		private const uint PROCESS_SET_SESSIONID = 0x0004;
		private const uint PROCESS_VM_OPERATION = 0x0008;
		private const uint PROCESS_VM_READ = 0x0010;
		private const uint PROCESS_VM_WRITE = 0x0020;
		private const uint PROCESS_DUP_HANDLE = 0x0040;
		private const uint PROCESS_CREATE_PROCESS = 0x0080;
		private const uint PROCESS_SET_QUOTA = 0x0100;
		private const uint PROCESS_SET_INFORMATION = 0x0200;
		private const uint PROCESS_QUERY_INFORMATION = 0x0400;

		[Flags]
		private enum SnapshotFlags : uint
		{
			HeapList = 0x00000001,
			Process = 0x00000002,
			Thread = 0x00000004,
			Module = 0x00000008,
			Module32 = 0x00000010,
			Inherit = 0x80000000,
			All = 0x0000001F
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
		private struct PROCESSENTRY32
		{
			const int MAX_PATH = 260;
			internal UInt32 dwSize;
			internal UInt32 cntUsage;
			internal UInt32 th32ProcessID;
			internal IntPtr th32DefaultHeapID;
			internal UInt32 th32ModuleID;
			internal UInt32 cntThreads;
			internal UInt32 th32ParentProcessID;
			internal Int32 pcPriClassBase;
			internal UInt32 dwFlags;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
			internal string szExeFile;
		}

		[DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
		static extern IntPtr CreateToolhelp32Snapshot([In] UInt32 dwFlags, [In] UInt32 th32ProcessID);

		[DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
		static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

		[DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
		static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);


		[DllImport("ntdll.dll", SetLastError = true)]
		static extern int NtQueryInformationProcess(IntPtr processHandle,
		   int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength,
		   out int returnLength);

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		private struct PROCESS_BASIC_INFORMATION
		{
			public int ExitStatus;
			public int PebBaseAddress;
			public int AffinityMask;
			public int BasePriority;
			public int UniqueProcessId;
			public int InheritedFromUniqueProcessId;

			public int Size
			{
				get { return (6 * 4); }
			}
		}

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		private struct TOKEN_PRIVILEGES
		{
			public int PrivilegeCount;
			public long Luid;
			public int Attributes;
		}

		private const int SE_PRIVILEGE_ENABLED = 0x00000002;
		private const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
		private const int TOKEN_QUERY = 0x00000008;

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		private static extern int OpenProcessToken(int ProcessHandle, int DesiredAccess, ref int tokenhandle);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		private static extern int GetCurrentProcess();

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		private static extern int LookupPrivilegeValue(string lpsystemname, string lpname, ref long lpLuid);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		private static extern int AdjustTokenPrivileges(int tokenhandle, int disableprivs, ref TOKEN_PRIVILEGES Newstate, int bufferlength, int PreivousState, int Returnlength);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		private static extern int GetSecurityInfo(int HANDLE, int SE_OBJECT_TYPE, int SECURITY_INFORMATION, int psidOwner, int psidGroup, out IntPtr pDACL, IntPtr pSACL, out IntPtr pSecurityDescriptor);

		[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
		private static extern int SetSecurityInfo(int HANDLE, int SE_OBJECT_TYPE, int SECURITY_INFORMATION, int psidOwner, int psidGroup, IntPtr pDACL, IntPtr pSACL);

		public void SetDirectoriesPath(ref DUMP_DIRECTORIES dpmdirs)
		{
			dpmdirs.dumps = Path.Combine(dpmdirs.root, "Sus_Dump");
			dpmdirs.nativedirname = Path.Combine(dpmdirs.dumps, "Native_Dump");
			dpmdirs.sysdirname = Path.Combine(dpmdirs.dumps, "System_Dump");
			dpmdirs.unknowndirname = Path.Combine(dpmdirs.dumps, "Unknown_Dump");
		}

		public struct DUMP_DIRECTORIES
		{
			public string root;
			public string dumps;
			public string nativedirname;
			public string sysdirname;
			public string unknowndirname;
		}

		public unsafe struct image_section_header
		{
			public fixed byte name[8];
			public int virtual_size;
			public int virtual_address;
			public int size_of_raw_data;
			public int pointer_to_raw_data;
			public int pointer_to_relocations;
			public int pointer_to_linenumbers;
			public short number_of_relocations;
			public short number_of_linenumbers;
			public int characteristics;
		};

		public struct IMAGE_FILE_HEADER
		{
			public short Machine;
			public short NumberOfSections;
			public int TimeDateStamp;
			public int PointerToSymbolTable;
			public int NumberOfSymbols;
			public short SizeOfOptionalHeader;
			public short Characteristics;
		}

		public int RVA2Offset(byte[] input, int rva)
		{
			int PEOffset = BitConverter.ToInt32(input, 0x3C);
			int nrofsection = (int)BitConverter.ToInt16(input, PEOffset + 0x06);

			for (int i = 0; i < nrofsection; i++)
			{
				int virtualAddress = BitConverter.ToInt32(input, PEOffset + 0x0F8 + 0x28 * i + 012);
				int fvirtualsize = BitConverter.ToInt32(input, PEOffset + 0x0F8 + 0x28 * i + 08);
				int frawAddress = BitConverter.ToInt32(input, PEOffset + 0x28 * i + 0x0F8 + 20);
				if ((virtualAddress <= rva) && (virtualAddress + fvirtualsize >= rva))
					return (frawAddress + (rva - virtualAddress));
			}

			return -1;
		}


		public int Offset2RVA(byte[] input, int offset)
		{
			int PEOffset = BitConverter.ToInt32(input, 0x3C);
			int nrofsection = (int)BitConverter.ToInt16(input, PEOffset + 0x06);

			for (int i = 0; i < nrofsection; i++)
			{
				int virtualAddress = BitConverter.ToInt32(input, PEOffset + 0x0F8 + 0x28 * i + 012);
				int virtualsize = BitConverter.ToInt32(input, PEOffset + 0x0F8 + 0x28 * i + 08);
				int frawAddress = BitConverter.ToInt32(input, PEOffset + 0x28 * i + 0x0F8 + 20);
				int frawsize = BitConverter.ToInt32(input, PEOffset + 0x28 * i + 0x0F8 + 16);
				if ((frawAddress <= offset) && (frawAddress + frawsize >= offset))
					return (virtualAddress + (offset - frawAddress));
			}

			return -1;
		}

		public bool CreateDirectories(ref DUMP_DIRECTORIES dpmdirs)
		{
			SetDirectoriesPath(ref dpmdirs);

			if (!Directory.Exists(dpmdirs.dumps))
				try { Directory.CreateDirectory(dpmdirs.dumps); } catch { }

			if (!Directory.Exists(dpmdirs.nativedirname))
				try { Directory.CreateDirectory(dpmdirs.nativedirname); } catch { }

			if (!Directory.Exists(dpmdirs.sysdirname))
				try { Directory.CreateDirectory(dpmdirs.sysdirname); } catch { }

			if (!Directory.Exists(dpmdirs.unknowndirname))
				try { Directory.CreateDirectory(dpmdirs.unknowndirname); } catch { }

			return true;
		}

		public unsafe void DumpProcess(int processId, string ProcessPath, bool dumpNative, bool restoreOriginalFilenames)
		{
			IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, Convert.ToUInt32(processId));

			if (hProcess == IntPtr.Zero)
			{
				IntPtr pDACL, pSecDesc;

				GetSecurityInfo((int)Process.GetCurrentProcess().Handle, 6, 4, 0, 0, out pDACL, IntPtr.Zero, out pSecDesc);
				hProcess = OpenProcess(0x40000, 0, Convert.ToUInt32(processId));
				SetSecurityInfo((int)hProcess, 6, 4 | 0x20000000, 0, 0, pDACL, IntPtr.Zero);
				CloseHandle(hProcess);
				hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, Convert.ToUInt32(processId));
			}

			if (hProcess != IntPtr.Zero)
			{
				uint minaddress = 0;
				uint maxaddress = 0xF0000000;
				uint pagesize = 0x1000;

				try
				{
					SYSTEM_INFO pSI = new SYSTEM_INFO();
					GetSystemInfo(ref pSI);
					minaddress = pSI.lpMinimumApplicationAddress;
					maxaddress = pSI.lpMaximumApplicationAddress;
					pagesize = pSI.dwPageSize;
				}
                catch { }

				int CurrentCount = 1;
				if (ProcessPath.Length < 2 || !Directory.Exists(ProcessPath))
					ProcessPath = "C:\\";

				DUMP_DIRECTORIES ddirs = new DUMP_DIRECTORIES();
				ddirs.root = ProcessPath;
				CreateDirectories(ref ddirs);

				bool isok;
				byte[] onepage = new byte[pagesize];
				uint BytesRead = 0;
				byte[] infokeep = new byte[8];

				for (uint j = minaddress; j < maxaddress; j += pagesize)
				{
					isok = ReadProcessMemory(hProcess, j, onepage, pagesize, ref BytesRead);
					if (isok)
					{
						for (int k = 0; k < onepage.Length - 2; k++)
						{
							if (onepage[k] == 0x4D && onepage[k + 1] == 0x5A)
							{
								if (ReadProcessMemory(hProcess, (uint)(j + k + 0x03C), infokeep, 4, ref BytesRead))
								{
									int PEOffset = BitConverter.ToInt32(infokeep, 0);
									if (PEOffset > 0 && (PEOffset + 0x0120) < pagesize)
									{
										if (ReadProcessMemory(hProcess, (uint)(j + k + PEOffset), infokeep, 2, ref BytesRead))
										{
											if (infokeep[0] == 0x050 && infokeep[1] == 0x045)
											{
												long NetMetadata = 0;
												if (ReadProcessMemory(hProcess, (uint)(j + k + PEOffset + 0x0E8), infokeep, 8, ref BytesRead))
													NetMetadata = BitConverter.ToInt64(infokeep, 0);

												if (dumpNative || NetMetadata != 0)
												{
													byte[] PeHeader = new byte[pagesize];
													if (ReadProcessMemory(hProcess, (uint)(j + k), PeHeader, pagesize, ref BytesRead))
													{
														int nrofsection = (int)BitConverter.ToInt16(PeHeader, PEOffset + 0x06);
														if (nrofsection > 0)
														{
															bool isNetFile = true;
															string dumpdir = "";
															if (NetMetadata == 0)
																isNetFile = false;

															int sectionalignment = BitConverter.ToInt32(PeHeader, PEOffset + 0x038);
															int filealignment = BitConverter.ToInt32(PeHeader, PEOffset + 0x03C);
															short sizeofoptionalheader = BitConverter.ToInt16(PeHeader, PEOffset + 0x014);

															bool IsDll = false;
															if ((PeHeader[PEOffset + 0x017] & 32) != 0) IsDll = true;
															IntPtr pointer = IntPtr.Zero;
															image_section_header[] sections = new image_section_header[nrofsection];
															uint ptr = (uint)(j + k + PEOffset) + (uint)sizeofoptionalheader + 4 +
																(uint)Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));

															for (int i = 0; i < nrofsection; i++)
															{
																byte[] datakeeper = new byte[Marshal.SizeOf(typeof(image_section_header))];
																ReadProcessMemory(hProcess, ptr, datakeeper, (uint)datakeeper.Length, ref BytesRead);
																fixed (byte* p = datakeeper)
																	pointer = (IntPtr)p;

																sections[i] = (image_section_header)Marshal.PtrToStructure(pointer, typeof(image_section_header));
																ptr = ptr + (uint)Marshal.SizeOf(typeof(image_section_header));
															}

															int totalrawsize = 0;
															int rawsizeoflast = sections[nrofsection - 1].size_of_raw_data;
															int rawaddressoflast = sections[nrofsection - 1].pointer_to_raw_data;
															if (rawsizeoflast > 0 && rawaddressoflast > 0)
																totalrawsize = rawsizeoflast + rawaddressoflast;
															
															string filename = "";

															int actualsizeofimage = BitConverter.ToInt32(PeHeader, PEOffset + 0x050);
															int sizeofimage = actualsizeofimage;
															int calculatedimagesize = BitConverter.ToInt32(PeHeader, PEOffset + 0x0F8 + 012);
															int rawsize, rawAddress, virtualsize, virtualAddress = 0;
															int calcrawsize = 0;

															for (int i = 0; i < nrofsection; i++)
															{
																virtualsize = sections[i].virtual_size;
																int toadd = (virtualsize % sectionalignment);
																if (toadd != 0) toadd = sectionalignment - toadd;
																calculatedimagesize = calculatedimagesize + virtualsize + toadd;
															}

															if (calculatedimagesize > sizeofimage) sizeofimage = calculatedimagesize;

															try
															{
																byte[] crap = new byte[totalrawsize];
															}
															catch
															{
																totalrawsize = sizeofimage;
															}

															if (totalrawsize != 0)
															{
																try
																{
																	byte[] rawdump = new byte[totalrawsize];
																	isok = ReadProcessMemory(hProcess, (uint)(j + k), rawdump, (uint)rawdump.Length, ref BytesRead);
																	if (isok)
																	{
																		dumpdir = ddirs.nativedirname;
																		if (isNetFile)
																			dumpdir = ddirs.dumps;

																		filename = dumpdir + "\\RAW_" + (j + k).ToString("X8");
																		if (File.Exists(filename))
																			filename = dumpdir + "\\RAW" + CurrentCount.ToString() + "_" + (j + k).ToString("X8");


																		if (IsDll)
																			filename = filename + ".dll";
																		else
																			filename = filename + ".exe";

																		try { File.WriteAllBytes(filename, rawdump); } catch { }

																		CurrentCount++;
																	}
																}
                                                                catch { }
															}

															byte[] virtualdump = new byte[sizeofimage];
															Array.Copy(PeHeader, virtualdump, pagesize);

															int rightrawsize = 0;
															for (int l = 0; l < nrofsection; l++)
															{
																rawsize = sections[l].size_of_raw_data;
																rawAddress = sections[l].pointer_to_raw_data;
																virtualsize = sections[l].virtual_size;
																virtualAddress = sections[l].virtual_address;

																calcrawsize = 0;
																calcrawsize = virtualsize % filealignment;
																if (calcrawsize != 0) calcrawsize = filealignment - calcrawsize;
																calcrawsize = virtualsize + calcrawsize;

																if (calcrawsize != 0 && rawsize != calcrawsize && rawsize != virtualsize || rawAddress < 0)
																{
																	rawsize = virtualsize;
																	rawAddress = virtualAddress;
																	BinaryWriter writer = new BinaryWriter(new MemoryStream(virtualdump));
																	writer.BaseStream.Position = PEOffset + 0x0F8 + 0x28 * l + 16;
																	writer.Write(virtualsize);
																	writer.BaseStream.Position = PEOffset + 0x0F8 + 0x28 * l + 20;
																	writer.Write(virtualAddress);
																	writer.Close();
																}

																byte[] csection = new byte[0];
																try { csection = new byte[rawsize]; } catch { csection = new byte[virtualsize]; }
																int rightsize = csection.Length;
																isok = ReadProcessMemory(hProcess, (uint)(j + k + virtualAddress), csection, (uint)rawsize, ref BytesRead);
																if (!isok || BytesRead != rawsize)
																{
																	rightsize = 0;
																	byte[] currentpage = new byte[pagesize];
																	for (int c = 0; c < rawsize; c = c + (int)pagesize)
																	{
																		try { isok = ReadProcessMemory(hProcess, (uint)(j + k + virtualAddress + c), currentpage, (uint)pagesize, ref BytesRead); } catch { break; }

																		if (isok)
																		{
																			rightsize = rightsize + (int)pagesize;
																			for (int i = 0; i < pagesize; i++)
																			{
																				if ((c + i) < csection.Length)
																					csection[c + i] = currentpage[i];
																			}
																		}
																	}
																}

																try { Array.Copy(csection, 0, virtualdump, rawAddress, rightsize); } catch { }

																if (l == nrofsection - 1)
																{
																	rightrawsize = rawAddress + rawsize;
																}
															}

															FixImportandEntryPoint((int)(j + k), virtualdump);

															dumpdir = ddirs.nativedirname;
															if (isNetFile)
																dumpdir = ddirs.dumps;

															filename = dumpdir + "\\VDUMP_" + (j + k).ToString("X8");
															if (File.Exists(filename))
																filename = dumpdir + "\\VDUMP" + CurrentCount.ToString() + "_" + (j + k).ToString("X8");

															if (IsDll)
																filename = filename + ".dll";
															else
																filename = filename + ".exe";

															FileStream fout = null;

															try { fout = new FileStream(filename, FileMode.Create); } catch { }

															if (fout != null)
															{
																if (rightrawsize > virtualdump.Length) rightrawsize = virtualdump.Length;

																fout.Write(virtualdump, 0, rightrawsize);
																fout.Close();
															}
															CurrentCount++;
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

				if (restoreOriginalFilenames)
				{
					if (Directory.Exists(ddirs.dumps))
					{
						DirectoryInfo di = new DirectoryInfo(ddirs.dumps);
						FileInfo[] rgFiles = di.GetFiles();

						foreach (FileInfo fi in rgFiles)
						{
							string placedir = ddirs.dumps;
							FileVersionInfo info = FileVersionInfo.GetVersionInfo(fi.FullName);
							if (info.CompanyName != null && info.CompanyName.ToLower().Contains("microsoft corporation") && (info.ProductName.ToLower().Contains(".net framework") || info.FileDescription.ToLower().Contains("runtime library")))
								placedir = ddirs.sysdirname;

							if (info.OriginalFilename != null && info.OriginalFilename != "")
							{
								string Newfilename = Path.Combine(placedir, info.OriginalFilename);
								int count = 2;
								if (File.Exists(Newfilename))
								{
									string extension = Path.GetExtension(Newfilename);
									if (extension == "") extension = ".dll";
									do
									{
										Newfilename = placedir + "\\" + Path.GetFileNameWithoutExtension(info.OriginalFilename) + "(" + count.ToString() + ")" + extension;
										count++;
									}
									while (File.Exists(Newfilename));
								}

								File.Move(fi.FullName, Newfilename);
							}
							else
							{
								string Newfilename = Path.Combine(ddirs.unknowndirname, fi.Name);
								int count = 2;
								if (File.Exists(Newfilename))
								{
									string extension = Path.GetExtension(fi.Name);

									do
									{
										Newfilename = ddirs.unknowndirname + "\\" + Path.GetFileNameWithoutExtension(fi.Name) + "(" + count.ToString() + ")" + extension;
										count++;
									}
									while (File.Exists(Newfilename));
								}

								File.Move(fi.FullName, Newfilename);
							}
						}
					}

					if (Directory.Exists(ddirs.nativedirname))
					{
						DirectoryInfo di = new DirectoryInfo(ddirs.nativedirname);
						FileInfo[] rgFiles = di.GetFiles();

						foreach (FileInfo fi in rgFiles)
						{
							FileVersionInfo info = FileVersionInfo.GetVersionInfo(fi.FullName);
							if (info.OriginalFilename != null && info.OriginalFilename != "")
							{
								string Newfilename = Path.Combine(ddirs.nativedirname, info.OriginalFilename);
								int count = 2;
								if (File.Exists(Newfilename))
								{
									string extension = Path.GetExtension(Newfilename);
									if (extension == "") extension = ".dll";
									do
									{
										Newfilename = ddirs.nativedirname + "\\" + Path.GetFileNameWithoutExtension(info.OriginalFilename) + "(" + count.ToString() + ")" + extension;
										count++;
									}
									while (File.Exists(Newfilename));
								}

								File.Move(fi.FullName, Newfilename);
							}
						}
					}
				}
				CurrentCount--;
				DumpLog = CurrentCount.ToString() + " files dumped in directory " + ddirs.dumps;

				CloseHandle(hProcess);
			}
		}

		public bool FixImportandEntryPoint(int dumpVA, byte[] Dump)
		{
			if (Dump == null || Dump.Length == 0) return false;

			int PEOffset = BitConverter.ToInt32(Dump, 0x3C);

			int ImportDirectoryRva = BitConverter.ToInt32(Dump, PEOffset + 0x080);
			int impdiroffset = RVA2Offset(Dump, ImportDirectoryRva);
			if (impdiroffset == -1) return false;

			byte[] mscoreeAscii = { 0x6D, 0x73, 0x63, 0x6F, 0x72, 0x65, 0x65, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };
			byte[] CorExeMain = { 0x5F, 0x43, 0x6F, 0x72, 0x45, 0x78, 0x65, 0x4D, 0x61, 0x69, 0x6E, 0x00 };
			byte[] CorDllMain = { 0x5F, 0x43, 0x6F, 0x72, 0x44, 0x6C, 0x6C, 0x4D, 0x61, 0x69, 0x6E, 0x00 };
			int ThunkToFix = 0;
			int ThunkData = 0;

			byte[] NameKeeper = new byte[mscoreeAscii.Length];
			int current = 0;
			int NameRVA = BitConverter.ToInt32(Dump, impdiroffset + current + 12);
			while (NameRVA > 0)
			{
				int NameOffset = RVA2Offset(Dump, NameRVA);
				if (NameOffset > 0)
				{
					try
					{
						bool ismscoree = true;
						for (int i = 0; i < mscoreeAscii.Length; i++)
						{
							if (Dump[NameOffset + i] != mscoreeAscii[i])
							{
								ismscoree = false;
								break;
							}
						}

						if (ismscoree)
						{
							int OriginalFirstThunk = BitConverter.ToInt32(Dump, impdiroffset + current);
							int OriginalFirstThunkfo = RVA2Offset(Dump, OriginalFirstThunk);
							if (OriginalFirstThunkfo > 0)
							{
								ThunkData = BitConverter.ToInt32(Dump, OriginalFirstThunkfo);
								int ThunkDatafo = RVA2Offset(Dump, ThunkData);
								if (ThunkDatafo > 0)
								{
									ismscoree = true;
									for (int i = 0; i < mscoreeAscii.Length; i++)
									{
										if (Dump[ThunkDatafo + 2 + i] != CorExeMain[i] && Dump[ThunkDatafo + 2 + i] != CorDllMain[i])
										{
											ismscoree = false;
											break;
										}
									}

									if (ismscoree)
									{
										ThunkToFix = BitConverter.ToInt32(Dump, impdiroffset + current + 16);
										break;
									}
								}
							}
						}
					}
					catch { }
				}

				try
				{
					current = current + 20;
					NameRVA = BitConverter.ToInt32(Dump, ImportDirectoryRva + current + 12);
				}
                catch { break; }
			}

			if (ThunkToFix <= 0 || ThunkData == 0) return false;

			int ThunkToFixfo = RVA2Offset(Dump, ThunkToFix);
			if (ThunkToFixfo < 0) return false;

			BinaryWriter writer = new BinaryWriter(new MemoryStream(Dump));
			int ThunkValue = BitConverter.ToInt32(Dump, ThunkToFixfo);
			if (ThunkValue <= 0 || RVA2Offset(Dump, ThunkValue) < 0)
			{
				writer.BaseStream.Position = ThunkToFixfo;
				writer.Write(ThunkData);
			}

			int EntryPoint = BitConverter.ToInt32(Dump, PEOffset + 0x028);
			if (EntryPoint <= 0 || RVA2Offset(Dump, EntryPoint) < 0)
			{
				byte[] ThunkToFixbytes = BitConverter.GetBytes((int)(ThunkToFix + dumpVA));
				for (int i = 0; i < Dump.Length - 6; i++)
				{
					if (Dump[i + 0] == 0x0FF && Dump[i + 1] == 0x025 && Dump[i + 2] == ThunkToFixbytes[0] && Dump[i + 3] == ThunkToFixbytes[1] && Dump[i + 4] == ThunkToFixbytes[2] && Dump[i + 5] == ThunkToFixbytes[3])
					{
						int EntrPointRVA = Offset2RVA(Dump, i);
						writer.BaseStream.Position = PEOffset + 0x028;
						writer.Write(EntrPointRVA);
						break;
					}
				}
			}

			writer.Close();
			return true;
		}
	}
}