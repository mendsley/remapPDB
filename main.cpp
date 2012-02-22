/*
Copyright (c) 2011 Matthew Endsley. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

THIS SOFTWARE IS PROVIDED BY MATTHEW ENDSLEY ``AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MATTHEW ENDSLEY OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define NOGDI

#include <stdio.h>
#include <io.h>
#include <Windows.h>
#include <DbgHelp.h>


static bool getExecutableChecksumAndSize( const char* _path, ULONG32* _timeStamp, IMAGE_OPTIONAL_HEADER* _header )
{
	FILE* fp = fopen(_path, "rb");
	if (!fp)
		return false;

	IMAGE_DOS_HEADER dosHeader;
	if (1 != fread(&dosHeader, sizeof(dosHeader), 1, fp))
	{
		fclose(fp);
		return false;
	}
	if (dosHeader.e_magic != 0x5A4D)
	{
		fclose(fp);
		return false;
	}

	fseek(fp, dosHeader.e_lfanew, SEEK_SET);
	IMAGE_NT_HEADERS ntHeader;
	if (1 != fread(&ntHeader, sizeof(ntHeader), 1, fp))
	{
		fclose(fp);
		return false;
	}
	fclose(fp);

	if (memcmp(&ntHeader.Signature, "PE\0\0", 4))
		return false;
	if (ntHeader.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER))
		return false;

	*_timeStamp = ntHeader.FileHeader.TimeDateStamp;
	*_header = ntHeader.OptionalHeader;
	return true;
}


static bool fixupDump( const char* _dumpPath, ULONG32 _timeStamp, const IMAGE_OPTIONAL_HEADER* _header, const char* _executablePath )
{
	FILE* fp = fopen(_dumpPath, "rb");
	if (!fp)
		return false;

	const long fileSize = _filelength(_fileno(fp));
	char* data = new char[fileSize];
	fread(data, fileSize, 1, fp);
	fclose(fp);

	MINIDUMP_HEADER* header = (MINIDUMP_HEADER*)data;
	header->CheckSum = 0;
	if (header->Signature != MINIDUMP_SIGNATURE)
	{
		delete[] data;
		return false;
	}


	MINIDUMP_DIRECTORY* directory = (MINIDUMP_DIRECTORY*)(data + header->StreamDirectoryRva);
	for (int ii = 0; ii < (int)header->NumberOfStreams; ++ii)
	{
		if (directory[ii].StreamType == ModuleListStream)
		{
			MINIDUMP_MODULE_LIST* moduleList = (MINIDUMP_MODULE_LIST*)(data + directory[ii].Location.Rva);

			MINIDUMP_MODULE* module = &moduleList->Modules[0];
			module->ModuleNameRva = fileSize;
			module->CheckSum = _header->CheckSum;
			module->SizeOfImage = _header->SizeOfImage;
			module->TimeDateStamp = _timeStamp;
		}
	}

	fp = fopen(_dumpPath, "wb");
	if (!fp)
	{
		delete[] data;
		return false;
	}

	fwrite(data, fileSize, 1, fp);

	wchar_t fullPath[MAX_PATH];
	GetCurrentDirectoryW(MAX_PATH, fullPath);
	wcscat(fullPath, L"\\");
	ULONG32 newSize = strlen(_executablePath) * sizeof(wchar_t) + wcslen(fullPath);
	fwrite(&newSize, sizeof(newSize), 1, fp);
	fwprintf(fp, L"%s%S", fullPath, _executablePath);
	fputc(0, fp);
	fclose(fp);

	delete[] data;
	return true;
}

static void cleanupDump( const char* _path )
{
	FILE* fp = fopen(_path, "rb");
	const long fileSize = _filelength(_fileno(fp));
	char* data = new char[fileSize];
	fread(data, fileSize, 1, fp);
	fclose(fp);


	MINIDUMP_HEADER* header = (MINIDUMP_HEADER*)data;
	const bool signatureMatches = (header->Signature == MINIDUMP_SIGNATURE);
	if (signatureMatches)
	{
		delete[] data;
		return;
	}

	header = (MINIDUMP_HEADER*)(data + 8);
	if (header->Signature != MINIDUMP_SIGNATURE)
	{
		delete[] data;
		return;
	}

	fp = fopen(_path, "wb");
	fwrite(data + 8, fileSize - 8, 1, fp);
	fclose(fp);
}


int main( int argc, char** argv )
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage: %s <exe filename>\n", argv[0]);
		return -1;
	}

	const char* executable = argv[1];

	// Find the checksum for the executable
	IMAGE_OPTIONAL_HEADER header;
	ULONG32 timeStamp;
	if (!getExecutableChecksumAndSize(executable, &timeStamp, &header))
	{
		fprintf(stderr, "Failed to lookup checksum for exe '%s'\n", executable);
		return -1;
	}

	// Fixup every .dmp file
	WIN32_FIND_DATAA findData;
	HANDLE handle = FindFirstFileA("*.dmp", &findData);
	if (handle != INVALID_HANDLE_VALUE)
	{
		do
		{
			cleanupDump(findData.cFileName);
			bool success = fixupDump(findData.cFileName, timeStamp, &header, executable);
			if (success)
			{
				printf("Remapped %s to %s\n", findData.cFileName, executable);
			}
			else
			{
				printf("** Failed to remap %s\n", findData.cFileName);
			}
		} while (FindNextFileA(handle, &findData));

		FindClose(handle);
	}

	return 0;
}
