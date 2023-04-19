// Copyright 2022 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// A very simple abstract API for working with potentially remote files.
// The implementation may use any file API, including the plain C FILE API, C++
// streams, or an actual API for dealing with remote files. The abstractions are
// the same as in the C FILE API.

#ifndef THIRD_PARTY_CENTIPEDE_REMOTE_FILE_H_
#define THIRD_PARTY_CENTIPEDE_REMOTE_FILE_H_

#include <filesystem>  // NOLINT
#include <string_view>

#include "./centipede/defs.h"

namespace centipede {

// An opaque file handle.
struct RemoteFile {};

// Opens a (potentially remote) file 'file_path' and returns a handle to it.
// Supported modes: "r", "a", "w", same as in C FILE API.
RemoteFile *RemoteFileOpen(std::string_view file_path, const char *mode);

// Closes the file previously opened by RemoteFileOpen.
void RemoteFileClose(RemoteFile *f);

// Appends bytes from 'ba' to 'f'.
void RemoteFileAppend(RemoteFile *f, const ByteArray &ba);

// Appends characters from 'contents' to 'f'.
void RemoteFileAppend(RemoteFile *f, const std::string &contents);

// Reads all current contents of 'f' into 'ba'.
void RemoteFileRead(RemoteFile *f, ByteArray &ba);

// Reads all current contents of 'f' into 'contents'.
void RemoteFileRead(RemoteFile *f, std::string &contents);

// Creates a (potentially remote) directory 'dir_path'.
// No-op if the directory already exists.
void RemoteMkdir(std::string_view dir_path);

// Sets the contents of the file at 'path' to 'contents'.
void RemoteFileSetContents(const std::filesystem::path &path,
                           const std::string &contents);

// Reads the contents of the file at 'path' into 'contents'.
void RemoteFileGetContents(const std::filesystem::path &path,
                           std::string &contents);

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_REMOTE_FILE_H_
