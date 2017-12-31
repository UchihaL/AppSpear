/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "elf_stripper.h"

#include <unistd.h>
#include <sys/types.h>
#include <memory>
#include <vector>

#include "base/logging.h"
#include "base/stringprintf.h"
#include "elf_file.h"
#include "elf_utils.h"
#include "utils.h"

namespace art {

bool ElfStripper::Strip(File* file, std::string* error_msg) {
  std::unique_ptr<ElfFile> elf_file(ElfFile::Open(file, true, false, error_msg));
  if (elf_file.get() == nullptr) {
    return false;
  }

  // ELF files produced by MCLinker look roughly like this
  //
  // +------------+
  // | Elf32_Ehdr | contains number of Elf32_Shdr and offset to first
  // +------------+
  // | Elf32_Phdr | program headers
  // | Elf32_Phdr |
  // | ...        |
  // | Elf32_Phdr |
  // +------------+
  // | section    | mixture of needed and unneeded sections
  // +------------+
  // | section    |
  // +------------+
  // | ...        |
  // +------------+
  // | section    |
  // +------------+
  // | Elf32_Shdr | section headers
  // | Elf32_Shdr |
  // | ...        | contains offset to section start
  // | Elf32_Shdr |
  // +------------+
  //
  // To strip:
  // - leave the Elf32_Ehdr and Elf32_Phdr values in place.
  // - walk the sections making a new set of Elf32_Shdr section headers for what we want to keep
  // - move the sections are keeping up to fill in gaps of sections we want to strip
  // - write new Elf32_Shdr section headers to end of file, updating Elf32_Ehdr
  // - truncate rest of file
  //

  std::vector<Elf32_Shdr> section_headers;
  std::vector<Elf32_Word> section_headers_original_indexes;
  section_headers.reserve(elf_file->GetSectionHeaderNum());


  Elf32_Shdr* string_section = elf_file->GetSectionNameStringSection();
  CHECK(string_section != nullptr);
  for (Elf32_Word i = 0; i < elf_file->GetSectionHeaderNum(); i++) {
    Elf32_Shdr* sh = elf_file->GetSectionHeader(i);
    CHECK(sh != nullptr);
    const char* name = elf_file->GetString(*string_section, sh->sh_name);
    if (name == nullptr) {
      CHECK_EQ(0U, i);
      section_headers.push_back(*sh);
      section_headers_original_indexes.push_back(0);
      continue;
    }
    if (StartsWith(name, ".debug")
        || (strcmp(name, ".strtab") == 0)
        || (strcmp(name, ".symtab") == 0)) {
      continue;
    }
    section_headers.push_back(*sh);
    section_headers_original_indexes.push_back(i);
  }
  CHECK_NE(0U, section_headers.size());
  CHECK_EQ(section_headers.size(), section_headers_original_indexes.size());

  // section 0 is the NULL section, sections start at offset of first section
  CHECK(elf_file->GetSectionHeader(1) != nullptr);
  Elf32_Off offset = elf_file->GetSectionHeader(1)->sh_offset;
  for (size_t i = 1; i < section_headers.size(); i++) {
    Elf32_Shdr& new_sh = section_headers[i];
    Elf32_Shdr* old_sh = elf_file->GetSectionHeader(section_headers_original_indexes[i]);
    CHECK(old_sh != nullptr);
    CHECK_EQ(new_sh.sh_name, old_sh->sh_name);
    if (old_sh->sh_addralign > 1) {
      offset = RoundUp(offset, old_sh->sh_addralign);
    }
    if (old_sh->sh_offset == offset) {
      // already in place
      offset += old_sh->sh_size;
      continue;
    }
    // shift section earlier
    memmove(elf_file->Begin() + offset,
            elf_file->Begin() + old_sh->sh_offset,
            old_sh->sh_size);
    new_sh.sh_offset = offset;
    offset += old_sh->sh_size;
  }

  Elf32_Off shoff = offset;
  size_t section_headers_size_in_bytes = section_headers.size() * sizeof(Elf32_Shdr);
  memcpy(elf_file->Begin() + offset, &section_headers[0], section_headers_size_in_bytes);
  offset += section_headers_size_in_bytes;

  elf_file->GetHeader().e_shnum = section_headers.size();
  elf_file->GetHeader().e_shoff = shoff;
  int result = ftruncate(file->Fd(), offset);
  if (result != 0) {
    *error_msg = StringPrintf("Failed to truncate while stripping ELF file: '%s': %s",
                              file->GetPath().c_str(), strerror(errno));
    return false;
  }
  return true;
}

}  // namespace art
