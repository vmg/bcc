/*
 * Copyright (c) 2016 GitHub, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <sstream>
#include <cstring>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "bcc_elf.h"
#include "bcc_proc.h"
#include "usdt.h"
#include "vendor/tinyformat.hpp"

namespace USDT {

Probe::Location::Location(uint64_t addr, const char *arg_fmt) : address_(addr) {
  ArgumentParser_x64 parser(arg_fmt);
  while (!parser.done()) {
    Argument *arg = new Argument();
    if (!parser.parse(arg)) {
      delete arg;  // TODO: report error
      continue;
    }
    arguments_.push_back(arg);
  }
}

Probe::Probe(const char *bin_path, const char *provider, const char *name,
             uint64_t semaphore)
    : bin_path_(bin_path),
      provider_(provider),
      name_(name),
      semaphore_(semaphore) {}

bool Probe::in_shared_object() {
  if (!in_shared_object_)
    in_shared_object_ = (bcc_elf_is_shared_obj(bin_path_.c_str()) == 1);
  return in_shared_object_.value();
}

bool Probe::resolve_global_address(uint64_t *global, const uint64_t addr, optional<int> pid) {
  if (in_shared_object()) {
    return (pid &&
	bcc_resolve_global_addr(*pid, bin_path_.c_str(), addr, global) == 0);
  }

  *global = addr;
  return true;
}

bool Probe::lookup_semaphore_addr(uint64_t *address, int pid) {
  auto it = semaphores_.find(pid);
  if (it != semaphores_.end()) {
    *address = it->second;
    return true;
  }

  if (!resolve_global_address(address, semaphore_, pid))
    return false;

  semaphores_[pid] = *address;
  return true;
}

bool Probe::add_to_semaphore(int pid, int16_t val) {
  uint64_t address;
  if (!lookup_semaphore_addr(&address, pid))
    return false;

  std::string procmem = tfm::format("/proc/%d/mem", pid);
  int memfd = ::open(procmem.c_str(), O_RDWR);
  if (memfd < 0)
    return false;

  int16_t original;  // TODO: should this be unsigned?

  if (::lseek(memfd, static_cast<off_t>(address), SEEK_SET) < 0 ||
      ::read(memfd, &original, 2) != 2) {
    ::close(memfd);
    return false;
  }

  original = original + val;

  if (::lseek(memfd, static_cast<off_t>(address), SEEK_SET) < 0 ||
      ::write(memfd, &original, 2) != 2) {
    ::close(memfd);
    return false;
  }

  ::close(memfd);
  return true;
}

bool Probe::enable(int pid) {
  if (!add_to_semaphore(pid, +1))
    return false;

  // TODO: what happens if we enable this twice?
  enabled_semaphores_.emplace(pid, std::move(ProcStat(pid)));
  return true;
}

bool Probe::disable(int pid) {
  auto it = enabled_semaphores_.find(pid);
  if (it == enabled_semaphores_.end())
    return false;

  bool result = true;
  if (!it->second.is_stale())
    result = add_to_semaphore(pid, -1);

  enabled_semaphores_.erase(it);
  return result;
}

bool Probe::usdt_thunks(std::ostream &stream, const std::string &prefix) {
  assert(!locations_.empty());
  for (size_t i = 0; i < locations_.size(); ++i) {
    tfm::format(
        stream,
        "int %s_thunk_%d(struct pt_regs *ctx) { return %s(ctx, %d); }\n",
        prefix, i, prefix, i);
  }
  return true;
}

bool Probe::usdt_cases(std::ostream &stream, const optional<int> &pid) {
  assert(!locations_.empty());
  const size_t arg_count = locations_[0].arguments_.size();

  for (size_t arg_n = 0; arg_n < arg_count; ++arg_n) {
    tfm::format(stream, "%s arg%d = 0;\n",
	largest_arg_type(arg_n), arg_n + 1);
  }

  for (size_t loc_n = 0; loc_n < locations_.size(); ++loc_n) {
    Location &location = locations_[loc_n];
    tfm::format(stream, "if (__loc_id == %d) {\n", loc_n);

    for (size_t arg_n = 0; arg_n < location.arguments_.size(); ++arg_n) {
      Argument *arg = location.arguments_[arg_n];
      if (!arg->assign_to_local(stream, tfm::format("arg%d", arg_n + 1),
                                bin_path_, pid))
        return false;
    }
    stream << "}\n";
  }
  return true;
}

std::string Probe::largest_arg_type(size_t arg_n) {
  Argument *largest = nullptr;
  for (Location &location : locations_) {
    Argument *candidate = location.arguments_[arg_n];
    if (!largest ||
	std::abs(candidate->arg_size()) > std::abs(largest->arg_size()))
      largest = candidate;
  }

  assert(largest);
  return largest->ctype();
}

bool Probe::usdt_getarg(std::ostream &stream, const optional<int> &pid) {
  const size_t arg_count = locations_[0].arguments_.size();

  if (arg_count == 0)
    return true;

  stream << "#include <uapi/linux/ptrace.h>\n";

  for (size_t arg_n = 0; arg_n < arg_count; ++arg_n) {
    std::string ctype = largest_arg_type(arg_n);
    tfm::format(stream,
      "static inline %s _bpf_readarg_%s_%d(struct pt_regs *ctx) {\n"
      "  %s result = 0x0;\n",
      ctype, name_, arg_n + 1, ctype);

    if (locations_.size() == 1) {
      Location &location = locations_.front();
      stream << "  ";
      if (!location.arguments_[arg_n]->assign_to_local(
	  stream, "result", bin_path_, pid))
	return false;
      stream << "\n";
    } else {
      for (Location &location : locations_) {
	uint64_t global_address;

	if (!resolve_global_address(&global_address, location.address_, pid))
	  return false;

	tfm::format(stream, "  if (ctx->ip == 0x%xULL) { ", global_address);
	if (!location.arguments_[arg_n]->assign_to_local(
	    stream, "result", bin_path_, pid))
	  return false;

	stream << "}\n";
      }
    }
    stream << "  return result;\n}\n";
  }
  return true;
}

void Probe::add_location(uint64_t addr, const char *fmt) {
  locations_.emplace_back(addr, fmt);
}

void Context::_each_probe(const char *binpath, const struct bcc_elf_usdt *probe,
                          void *p) {
  Context *ctx = static_cast<Context *>(p);
  ctx->add_probe(binpath, probe);
}

int Context::_each_module(const char *modpath, uint64_t, uint64_t, void *p) {
  bcc_elf_foreach_usdt(modpath, _each_probe, p);
  return 0;
}

void Context::add_probe(const char *binpath, const struct bcc_elf_usdt *probe) {
  Probe *found_probe = nullptr;

  for (Probe *p : probes_) {
    if (p->provider_ == probe->provider && p->name_ == probe->name) {
      found_probe = p;
      break;
    }
  }

  if (!found_probe) {
    found_probe =
        new Probe(binpath, probe->provider, probe->name, probe->semaphore);
    probes_.push_back(found_probe);
  }

  found_probe->add_location(probe->pc, probe->arg_fmt);
}

std::string Context::resolve_bin_path(const std::string &bin_path) {
  std::string result;

  if (char *which = bcc_procutils_which(bin_path.c_str())) {
    result = which;
    ::free(which);
  } else if (const char *which_so = bcc_procutils_which_so(bin_path.c_str())) {
    result = which_so;
  }

  return result;
}

Probe *Context::get(const std::string &probe_name) const {
  for (Probe *p : probes_) {
    if (p->name_ == probe_name)
      return p;
  }
  return nullptr;
}

int Context::get_idx(const std::string &probe_name) const {
  const int probe_count = static_cast<int>(probes_.size());
  for (int i = 0; i < probe_count; ++i) {
    if (probes_[i]->name_ == probe_name)
      return i;
  }
  return -1;
}

Context::Context(const std::string &bin_path) : loaded_(false) {
  std::string full_path = resolve_bin_path(bin_path);
  if (!full_path.empty()) {
    if (bcc_elf_foreach_usdt(full_path.c_str(), _each_probe, this) == 0)
      loaded_ = true;
  }
}

Context::Context(int pid) : pid_(pid), loaded_(false) {
  if (bcc_procutils_each_module(pid, _each_module, this) == 0)
    loaded_ = true;
}
}

extern "C" {
void *bcc_usdt_new_frompid(int pid) {
  return static_cast<void *>(new USDT::Context(pid));
}

void *bcc_usdt_new_frompath(const char *path) {
  return static_cast<void *>(new USDT::Context(path));
}

int bcc_usdt_loaded(void *usdt) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  return ctx->loaded();
}

int bcc_usdt_find_probe(void *usdt, const char *probe_name) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  return ctx->get_idx(probe_name);
}

char *bcc_usdt_probe_boilerplate(void *usdt, int fd) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(fd);

  std::ostringstream stream;
  if (!probe->usdt_getarg(stream, ctx->pid()))
    return nullptr;
  return strdup(stream.str().c_str());
}

int bcc_usdt_probe_need_enable(void *usdt, int fd) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(fd);
  return probe->need_enable();
}

int bcc_usdt_probe_enable(void *usdt, int fd) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(fd);
  auto pid = ctx->pid();
  return (pid && probe->enable(*pid)) ? 0 : -1;
}

int bcc_usdt_probe_disable(void *usdt, int fd) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(fd);
  auto pid = ctx->pid();
  return (pid && probe->disable(*pid)) ? 0 : -1;
}

size_t bcc_usdt_probe_location_count(void *usdt, int fd) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(fd);
  return probe->num_locations();
}

uint64_t bcc_usdt_probe_address(void *usdt, int fd, size_t loc) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(fd);
  return probe->address(loc);
}

const char *bcc_usdt_probe_binpath(void *usdt, int fd) {
  USDT::Context *ctx = static_cast<USDT::Context *>(usdt);
  USDT::Probe *probe = ctx->get(fd);
  return probe->bin_path().c_str();
}

}
