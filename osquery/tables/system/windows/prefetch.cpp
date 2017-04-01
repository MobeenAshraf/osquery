#include <Windows.h>
#include<compressapi.h>
#include <stdio.h>
#include<iostream>
#include<fstream>
#include<string>
#include <boost/date_time.hpp>
#include<vector>
#include <algorithm>
#include <boost/filesystem.hpp>
#include <osquery/filesystem.h>
#include <osquery/sql.h>
#include <osquery/system.h>
#include <osquery/tables.h>
#include "osquery/core/conversions.h"
#include "osquery/core/windows/wmi.h"
#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/date_time/posix_time/posix_time_types.hpp"
#include<chrono>
using namespace std;
NTSTATUS(__stdcall *RtlDecompressBufferEx)(
	_In_  USHORT CompressionFormat,
	_Out_ PUCHAR UncompressedBuffer,
	_In_  ULONG  UncompressedBufferSize,
	_In_  PUCHAR CompressedBuffer,
	_In_  ULONG  CompressedBufferSize,
	_Out_ PULONG FinalUncompressedSize,
	_In_  PVOID  WorkSpace
	);

NTSTATUS(__stdcall *RtlGetCompressionWorkSpaceSize)(
	_In_   USHORT CompressionFormatAndEngine,
	_Out_  PULONG CompressBufferWorkSpaceSize,
	_Out_  PULONG CompressFragmentWorkSpaceSize
	);



PBYTE decompresor(int calgo,vector<char> buffer, ULONG SizeBuff)
{
   
	DECOMPRESSOR_HANDLE Decompressor = NULL;
	PBYTE CompressedBuffer = NULL;
	PBYTE DecompressedBuffer = NULL;
	
	HANDLE DecompressedFile = INVALID_HANDLE_VALUE;
	BOOL DeleteTargetFile = TRUE;
	BOOL Success=false;
	
	ULONG InputFileSize;
	
	


	InputFileSize = static_cast<ULONG>(buffer.size() - 8);
	 

	//  Allocation memory for compressed content.
	CompressedBuffer = (PBYTE)malloc(InputFileSize);
	if (!CompressedBuffer)
	{
		//Cannot allocate memory for compressed buffer
		goto done;
	}

	for (int i = 8; i<buffer.size(); i++)
		CompressedBuffer[i - 8] = buffer[i];



	ULONG CompressBufferWorkSpaceSize = 0, CompressFragmentWorkSpaceSize = 0;

	//  Query decompressed buffer size.
	RtlDecompressBufferEx = (long(__stdcall *)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID))GetProcAddress(GetModuleHandleA("ntdll"), "RtlDecompressBufferEx");
	if (RtlDecompressBufferEx == NULL)
	{
		// GetProcAddress() failed
		goto done;
	}

	RtlGetCompressionWorkSpaceSize = (long(__stdcall *)(USHORT, PULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetCompressionWorkSpaceSize");
	if (RtlGetCompressionWorkSpaceSize == NULL)
	{
		
		goto done;
	}
	if (RtlGetCompressionWorkSpaceSize(USHORT(calgo), &CompressBufferWorkSpaceSize, &CompressFragmentWorkSpaceSize) != 0)
	{
		
		goto done;
	}
	
	PUCHAR pBuffer = new UCHAR[SizeBuff];
	
	if (pBuffer == NULL)
	{
		//VirtualAlloc() failed
		goto done;
	}
	ULONG FinalUnComp=0;
	//PUCHAR pCompressedBuffer = CompressedBuffer;

	
	
	PVOID  WorkSpace = new UCHAR*[CompressFragmentWorkSpaceSize];
	if (RtlDecompressBufferEx(USHORT(calgo),(pBuffer),SizeBuff, CompressedBuffer,InputFileSize,&FinalUnComp,WorkSpace) != 0)
	{
		// RtlDecompressBuffer() failed
		goto done;
	}
	else
	{
		//return pBuffer
		Success = true;
		
	}
	VirtualFree(pBuffer, SizeBuff, 0);

	

	

done:	
	if (CompressedBuffer)
	{
		free(CompressedBuffer);
	}

	if (DecompressedBuffer)
	{
		free(DecompressedBuffer);
	}

	

	if (DecompressedFile != INVALID_HANDLE_VALUE)
	{
		//  Compression fails, delete the compressed file.
		if (DeleteTargetFile)
		{
			FILE_DISPOSITION_INFO fdi;
			fdi.DeleteFile = TRUE;      //  Marking for deletion
			Success = SetFileInformationByHandle(
				DecompressedFile,
				FileDispositionInfo,
				&fdi,
				sizeof(FILE_DISPOSITION_INFO));
			if (!Success) {
				//wprintf(L"Cannot delete corrupted decompressed file.\n");
			}
		}
		CloseHandle(DecompressedFile);
	}
	
	return pBuffer;
	
}








static string Read(istream &stream, uint32_t count)
{
	std::vector<char> result(count+1);  // Because vector is guranteed to be contiguous in C++03
	stream.read(&result[0], count+1);

	return std::string(&result[count - 4], &result[count ]);
}





namespace osquery  {
	namespace tables {

		QueryData genPrefetchInfo(QueryContext& context) {
			QueryData results;
			boost::system::error_code ec;
			auto paths = context.constraints["path"].getAll(EQUALS);
			
		
			for (const auto &path_string : paths) {
				boost::filesystem::path path = path_string;
				string extension = boost::filesystem::extension(path.string());
				if ((!boost::filesystem::is_regular_file(path, ec))) {
					continue;
				}










				Row r;


				ifstream infile(path.string(), ios::in | ios::binary);
				if (!infile) { exit(1); }

				std::vector<char> buffer((
					std::istreambuf_iterator<char>(infile)),
					(std::istreambuf_iterator<char>()));

				infile.seekg(0, infile.beg);
				string Enc_type = Read(infile, 4);


				int sign = 0,  calgo = 0, crc_check = 0, magic = 0;
				size_t decompressedSize=0;
				if (Enc_type.substr(0, 3) == "MAM") {
					// file is for windows 10
					//MAM encoded  , decompress for win 10
					sign += Enc_type[0] | (Enc_type[1] << 8) | (Enc_type[2] << 16) | (Enc_type[3] << 24);
					decompressedSize += buffer[4] | (buffer[5] << 8) | (buffer[6] << 16) | (buffer[7] << 24);
					stringstream ss;

					ss << decompressedSize;

					
					r["file_size"] = ss.str();
					calgo = (sign & 0x0F000000) >> 24;
					crc_check = (sign & 0xF0000000) >> 28;
					magic = sign & 0x00FFFFFF;
					if (magic != 0x004d414d)
					{
						//wrong file
					//	return 0;
						continue;
					}
					if (!crc_check) {
						//crc is valid
						size_t compressed_size = (buffer.size()) - 8;

						PBYTE decompressed = decompresor(calgo, buffer, static_cast<ULONG>(decompressedSize));
						//cout << "Compressed Size " << compressed_size << endl;;
						PBYTE newStr = new BYTE[4 + 1];
						memcpy(newStr, decompressed, 4);
						newStr[5] = '\0';
						unsigned int version = *((unsigned int*)newStr);
						r["version"] = std::to_string(version);

						memcpy(newStr, decompressed + 4, 4);
						unsigned int signature = *((unsigned int*)newStr);
						r["signature"] = std::to_string(signature);

						PBYTE exeName = new BYTE[60 + 1];
						memcpy(exeName, decompressed + 16, 60);
						exeName[61] = '\0';
						int chk = 2;
						const char *p = reinterpret_cast<const char*>(exeName);
						string exe = "";
						int i = 0;
						while (p[i] != '\0') {
							exe += p[i];
							i++;
							if (p[i] == '\0') {
								i++;
							}
						}



						memcpy(newStr, decompressed + 208, 4);
						unsigned int runCount = *((unsigned int*)newStr);


						PBYTE a = new BYTE[9];
						memcpy(a, decompressed + 128, 9);
						unsigned long long time = *((unsigned long long*)a);
						boost::posix_time::ptime myEpoch(boost::gregorian::date(1601, boost::gregorian::Jan, 1));
						

						//// convert back to ptime
						boost::posix_time::ptime test = myEpoch + boost::posix_time::milliseconds(time/10);
				
						r["last_executed"] =  std::to_string(time);
						r["executable_name"] = exe;
						r["run_count"] = std::to_string(runCount);
						r["path"] = path.string();

						free(newStr);
						free(a);
						free(decompressed);

					}
				}




				infile.close();







				results.push_back(r);

			}
			return results;
		}
	}
}